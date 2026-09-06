/**
 * Wire types returned by the AEGISX backend (FastAPI, camelCase JSON).
 *
 * These mirror the Pydantic schemas in `backend/app/schemas`. UI-facing types
 * live next to their feature; the mappers in this folder translate between the
 * two so component props never change shape when the API evolves.
 */

import type {
  ApiAIAnalysis,
  ApiCorrelationAnalytics,
  ApiMLAnalytics,
  ApiMLFinding,
  ApiRiskSignal,
  ApiSequence,
  ApiThreatIntelAnalytics,
} from "./mlTypes";

export type Severity = "Low" | "Medium" | "High" | "Critical";
export type EventStatus = "New" | "Investigating" | "Resolved";
/**
 * The full incident lifecycle (V9 Phase B).
 *
 * This listed only four states until Phase I - the backend had returned seven
 * since Phase B, so a `Triaged` or `Closed` incident was a value TypeScript
 * insisted could not exist. Nothing crashed, which is why it survived: the
 * types were simply wrong about the running system.
 *
 * Which state may follow which is the backend's business, not this file's -
 * see `GET /incidents/{id}/transitions`.
 */
export type IncidentStatus =
  | "Open"
  | "Triaged"
  | "Investigating"
  | "Containment Pending"
  | "Contained"
  | "Resolved"
  | "Closed";
export type NotificationSeverity = "low" | "medium" | "high" | "critical";
export type NotificationCategory =
  | "event"
  | "incident"
  | "assignment"
  | "response"
  | "system";

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface ApiUser {
  id: number;
  email: string;
  fullName: string;
  role: "admin" | "analyst" | "viewer";
  isActive: boolean;
  lastLoginAt: string | null;
  createdAt: string;
  /** Effective permissions for this role, as enforced by the backend. */
  permissions?: string[];
}

export interface ApiToken {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  user: ApiUser;
  permissions: string[];
}

export interface ApiIOC {
  id: number;
  type: string;
  value: string;
  description: string | null;
  severity: Severity;
  confidence: number;
  source: string | null;
  sightingCount: number;
  firstSeen: string;
  lastSeen: string;
}

export type {
  ApiAIAnalysis,
  ApiMLFinding,
  ApiRiskSignal,
  ApiSequence,
  ApiThreatIntel,
} from "./mlTypes";

/** Why a rule fired. Produced by deterministic rules - never a model. */
export interface ApiDetection {
  ruleId: string;
  ruleVersion: string;
  ruleName: string;
  reason: string;
  severity: Severity;
  riskContribution: number;
  mitreTechniques: string[];
  matchedAt: string;
}

export interface ApiEvent {
  id: string;
  timestamp: string;
  source: string;
  sourceType: string;
  eventType: string;
  title: string;
  description: string | null;
  severity: Severity;
  status: EventStatus;
  riskScore: number;
  hostname: string | null;
  username: string | null;
  sourceIp: string | null;
  destinationIp: string | null;
  destinationPort: number | null;
  process: string | null;
  commandLine: string | null;
  rawLog: string | null;
  normalizedData: Record<string, unknown>;
  mitreTechniques: string[];
  detectionRules: string[];
  detections: ApiDetection[];
  /** V3: severity band of the hybrid score. Raises the rule severity, never lowers it. */
  riskLevel: Severity;
  /** V3: every contribution to `riskScore`, named by source. */
  riskSignals: ApiRiskSignal[];
  /** V3: anomaly model verdicts. Empty can mean "not scored", not "not anomalous". */
  mlFindings: ApiMLFinding[];
  isSynthetic: boolean;
  incidentId: string | null;
  iocs: ApiIOC[];
  createdAt: string;
}

export interface ApiIncidentEvent {
  id: string;
  timestamp: string;
  source: string;
  title: string;
  severity: Severity;
  status: string;
  riskScore: number;
  isAnomaly: boolean;
  anomalyScore: number | null;
}

export interface ApiTimelineEntry {
  timestamp: string;
  action: string;
  actor: string;
  detail: string;
}

export interface ApiIncident {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  source: string;
  analyst: string;
  assigneeId: number | null;
  riskScore: number;
  mitreTechniques: string[];
  /** V3: aggregated signal breakdown across the incident's events. */
  riskSignals: ApiRiskSignal[];
  /** V3: correlated sequences any of these events belong to. */
  sequences: ApiSequence[];
  /** V3: AI analyses, newest first. Always labelled AI-generated. */
  aiAnalyses: ApiAIAnalysis[];
  mlAnomalyCount: number;
  timeline: ApiTimelineEntry[];
  eventIds: string[];
  events: ApiIncidentEvent[];
  iocs: ApiIOC[];
  eventCount: number;
  createdAt: string;
  updatedAt: string;
  resolvedAt: string | null;
}

export interface ApiNotification {
  id: number;
  title: string;
  description: string;
  severity: NotificationSeverity;
  category: NotificationCategory;
  isRead: boolean;
  eventId: string | null;
  incidentId: string | null;
  createdAt: string;
}

export interface ApiNotificationCounts {
  total: number;
  unread: number;
}

export interface ApiCountByKey {
  key: string;
  count: number;
}

export interface ApiTimeBucket {
  bucket: string;
  count: number;
  critical: number;
  high: number;
}

export interface ApiAnalystWorkload {
  analyst: string;
  open: number;
  investigating: number;
  contained: number;
  resolved: number;
  total: number;
}

export interface ApiAnalyticsSummary {
  totalEvents: number;
  criticalEvents: number;
  highEvents: number;
  newEvents: number;
  openIncidents: number;
  criticalIncidents: number;
  resolvedIncidents: number;
  totalIncidents: number;
  totalIocs: number;
  meanRiskScore: number;
  eventsBySeverity: ApiCountByKey[];
  incidentsBySeverity: ApiCountByKey[];
  eventsBySource: ApiCountByKey[];
  eventsBySourceType: ApiCountByKey[];
  mitreCoverage: ApiCountByKey[];
  eventsOverTime: ApiTimeBucket[];
  incidentsOverTime: ApiTimeBucket[];
  analystWorkload: ApiAnalystWorkload[];
  /** V3 - null only if the backend predates this release. */
  ml: ApiMLAnalytics | null;
  correlation: ApiCorrelationAnalytics | null;
  threatIntel: ApiThreatIntelAnalytics | null;
  windowHours: number;
  generatedAt: string;
}

export interface ApiTelemetryStatus {
  running: boolean;
  intervalSeconds: number;
  eventsPerTick: number;
  eventsIngested: number;
  errors: number;
  startedAt: string | null;
  lastTickAt: string | null;
  sources: { name: string; sourceType: string; isExternal: boolean }[];
  externalSourcesAllowed: boolean;
}


// --- Detection engine transparency ------------------------------------------

export interface ApiDetectionRule {
  id: string;
  version: string;
  legacyId: string | null;
  name: string;
  description: string;
  severity: Severity;
  riskContribution: number;
  mitreTechniques: string[];
  labels: string[];
}

export interface ApiRuleCatalogue {
  engine: string;
  usesMachineLearning: boolean;
  ruleCount: number;
  rulesetFingerprint: string;
  rules: ApiDetectionRule[];
}

export interface ApiConfusion {
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  total: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  falsePositiveRate: number | null;
  falseNegativeRate: number | null;
  accuracy: number | null;
  specificity: number | null;
  sufficientData: boolean;
}

export interface ApiClassResult {
  label: string;
  total: number;
  detected: number;
  missed: number;
  detectionRate: number | null;
  coveredByRules: boolean;
  sufficientData: boolean;
  ruleHits: Record<string, number>;
}

export interface ApiRuleResult {
  ruleId: string;
  ruleVersion: string;
  ruleName: string;
  fires: number;
  onMalicious: number;
  onBenign: number;
  correctClass: number;
  wrongClass: number;
  rulePrecision: number | null;
  attributionAccuracy: number | null;
}

export interface ApiDetectionQuality {
  schemaVersion: string;
  generatedAt: string;
  dataset: {
    name: string;
    version: string;
    seed: number;
    fingerprint: string;
    totalEvents: number;
    maliciousEvents: number;
    benignEvents: number;
    classCounts: Record<string, number>;
    generator: string;
  };
  engine: {
    type: string;
    ruleCount: number;
    fingerprint: string;
    rules: { id: string; version: string; legacyId: string | null }[];
  };
  overall: ApiConfusion;
  perClass: ApiClassResult[];
  perRule: ApiRuleResult[];
  latency: {
    measured: string;
    samples: number;
    meanMs: number;
    p50Ms: number;
    p95Ms: number;
    p99Ms: number;
    maxMs: number;
    minMs: number;
    totalMs: number;
    eventsPerSecond: number;
  };
  volume: {
    eventsProcessed: number;
    maliciousEvents: number;
    benignEvents: number;
    alertsGenerated: number;
    detectionsTotal: number;
    incidentCandidates: number;
  };
  coverage: {
    coveredLabels: string[];
    uncoveredLabels: string[];
    minSamplesOverall: number;
    minSamplesPerClass: number;
  };
  notes: string[];
  /** True when the report was produced by a different ruleset than the one running. */
  stale?: boolean;
  currentRulesetFingerprint?: string;
}

export type ComponentStatus = "healthy" | "degraded" | "unavailable";

export interface ApiSystemHealth {
  status: ComponentStatus;
  checkedAt: string;
  app: {
    status: ComponentStatus;
    name: string;
    version: string;
    environment: string;
    uptimeSeconds: number;
  };
  database: { status: ComponentStatus; latencyMs?: number; dialect?: string };
  telemetry: {
    status: ComponentStatus;
    reason?: string | null;
    running: boolean;
    intervalSeconds?: number;
    eventsIngested?: number;
    errors?: number;
    secondsSinceLastTick?: number | null;
  };
  realtime: { status: ComponentStatus; connectedClients: number };
}
