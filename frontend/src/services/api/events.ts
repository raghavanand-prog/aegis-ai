/** Event endpoints. */

import type { Event } from "@/features/events/types";
import { formatClockTime } from "@/lib/time";

import { api } from "./client";
import type { ApiEvent, ApiIncident, EventStatus, Page, Severity } from "./types";
import { toUiIncident } from "./incidents";
import type { Incident } from "@/features/incidents/types";

export interface EventQuery {
  search?: string;
  severity?: Severity | "All";
  status?: EventStatus;
  source?: string;
  sourceType?: string;
  /** V3: restrict to events the anomaly model flagged. */
  isAnomaly?: boolean;
  limit?: number;
  offset?: number;
}

/** Map the API payload onto the shape the Events UI renders. */
export function toUiEvent(dto: ApiEvent): Event {
  return {
    id: dto.id,
    time: formatClockTime(dto.timestamp),
    source: dto.source,
    event: dto.title,
    severity: dto.severity,
    status: dto.status,

    timestamp: dto.timestamp,
    sourceType: dto.sourceType,
    eventType: dto.eventType,
    description: dto.description,
    riskScore: dto.riskScore,
    hostname: dto.hostname,
    username: dto.username,
    sourceIp: dto.sourceIp,
    destinationIp: dto.destinationIp,
    destinationPort: dto.destinationPort,
    process: dto.process,
    commandLine: dto.commandLine,
    rawLog: dto.rawLog,
    normalizedData: dto.normalizedData,
    mitreTechniques: dto.mitreTechniques,
    detectionRules: dto.detectionRules,
    detections: dto.detections,
    riskLevel: dto.riskLevel,
    riskSignals: dto.riskSignals,
    mlFindings: dto.mlFindings,
    isSynthetic: dto.isSynthetic,
    incidentId: dto.incidentId,
    iocs: dto.iocs?.map((ioc) => ({
      id: ioc.id,
      type: ioc.type,
      value: ioc.value,
      severity: ioc.severity,
      confidence: ioc.confidence,
      sightingCount: ioc.sightingCount,
    })),
  };
}

function toParams(query: EventQuery): Record<string, string | number> {
  const params: Record<string, string | number> = {
    limit: query.limit ?? 100,
    offset: query.offset ?? 0,
  };
  if (query.search) params.search = query.search;
  if (query.severity && query.severity !== "All") params.severity = query.severity;
  if (query.status) params.status = query.status;
  if (query.source) params.source = query.source;
  if (query.sourceType) params.sourceType = query.sourceType;
  if (query.isAnomaly !== undefined) params.isAnomaly = String(query.isAnomaly);
  return params;
}

export interface EventsResult {
  events: Event[];
  total: number;
}

export async function fetchEvents(query: EventQuery = {}): Promise<EventsResult> {
  const { data } = await api.get<Page<ApiEvent>>("/events", { params: toParams(query) });
  return { events: data.items.map(toUiEvent), total: data.total };
}

export async function fetchEvent(eventId: string): Promise<Event> {
  const { data } = await api.get<ApiEvent>(`/events/${eventId}`);
  return toUiEvent(data);
}

export async function updateEventStatus(
  eventId: string,
  status: EventStatus,
): Promise<Event> {
  const { data } = await api.patch<ApiEvent>(`/events/${eventId}/status`, { status });
  return toUiEvent(data);
}

export interface PromoteOptions {
  title?: string;
  description?: string;
  severity?: Severity;
  analyst?: string;
}

/** Promote an event into a new incident. */
export async function promoteEvent(
  eventId: string,
  options: PromoteOptions = {},
): Promise<Incident> {
  const { data } = await api.post<ApiIncident>(`/events/${eventId}/promote`, options);
  return toUiIncident(data);
}
