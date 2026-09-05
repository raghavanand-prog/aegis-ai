import type { IncidentStatus } from "@/services/api/types";

/**
 * Incident shape used by the Incidents UI.
 *
 * As with events, the original fields stay required so existing components are
 * untouched; backend detail is added as optional fields.
 */

export interface IncidentTimelineEntry {
  timestamp: string;
  action: string;
  actor: string;
  detail: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  description: string;
  status: IncidentStatus;
  analyst: string;
  source: string;
  created: string;

  /** Enriched fields supplied by the backend. */
  createdAt?: string;
  updatedAt?: string;
  resolvedAt?: string | null;
  riskScore?: number;
  mitreTechniques?: string[];
  timeline?: IncidentTimelineEntry[];
  eventIds?: string[];
  eventCount?: number;
  iocs?: { id: number; type: string; value: string; severity: string }[];
}
