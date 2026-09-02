/**
 * Event shape used by the Events UI.
 *
 * The first six fields are what the tables, filters and drawer render; the
 * rest is the enriched detail the backend now provides (detection results,
 * entities, raw telemetry). Everything past `status` is optional so any
 * component written against the original mock data keeps compiling.
 */

import type { ApiMLFinding, ApiRiskSignal } from "@/services/api/mlTypes";

export interface EventIOC {
  id: number;
  type: string;
  value: string;
  severity: string;
  confidence: number;
  sightingCount: number;
}

/** A single rule match, with the reason it fired. */
export interface DetectionExplanation {
  ruleId: string;
  ruleVersion: string;
  ruleName: string;
  reason: string;
  severity: string;
  riskContribution: number;
  mitreTechniques: string[];
  matchedAt: string;
}

export interface Event {
  id: string;
  time: string;
  source: string;
  event: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  status: "New" | "Investigating" | "Resolved";

  /** Enriched fields supplied by the backend. */
  timestamp?: string;
  sourceType?: string;
  eventType?: string;
  description?: string | null;
  riskScore?: number;
  hostname?: string | null;
  username?: string | null;
  sourceIp?: string | null;
  destinationIp?: string | null;
  destinationPort?: number | null;
  process?: string | null;
  commandLine?: string | null;
  rawLog?: string | null;
  normalizedData?: Record<string, unknown>;
  mitreTechniques?: string[];
  detectionRules?: string[];
  detections?: DetectionExplanation[];
  /** V3: severity band of the hybrid score. */
  riskLevel?: string;
  /** V3: every contribution to `riskScore`, named by source. */
  riskSignals?: ApiRiskSignal[];
  /** V3: anomaly model verdicts. Empty can mean "not scored", not "normal". */
  mlFindings?: ApiMLFinding[];
  isSynthetic?: boolean;
  incidentId?: string | null;
  iocs?: EventIOC[];
}
