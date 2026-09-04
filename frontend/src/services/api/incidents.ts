/** Incident endpoints. */

import type { Incident } from "@/features/incidents/types";
import { relativeTime } from "@/lib/time";

import { api } from "./client";
import type { ApiIncident, IncidentStatus, Page, Severity } from "./types";

export interface IncidentQuery {
  search?: string;
  severity?: Severity | "All";
  status?: IncidentStatus;
  limit?: number;
  offset?: number;
}

export function toUiIncident(dto: ApiIncident): Incident {
  return {
    id: dto.id,
    title: dto.title,
    severity: dto.severity,
    description: dto.description,
    status: dto.status,
    analyst: dto.analyst,
    source: dto.source,
    created: relativeTime(dto.createdAt),

    createdAt: dto.createdAt,
    updatedAt: dto.updatedAt,
    resolvedAt: dto.resolvedAt,
    riskScore: dto.riskScore,
    mitreTechniques: dto.mitreTechniques,
    timeline: dto.timeline,
    eventIds: dto.eventIds,
    eventCount: dto.eventCount,
    iocs: dto.iocs?.map((ioc) => ({
      id: ioc.id,
      type: ioc.type,
      value: ioc.value,
      severity: ioc.severity,
    })),
  };
}

export interface IncidentsResult {
  incidents: Incident[];
  total: number;
}

export async function fetchIncidents(query: IncidentQuery = {}): Promise<IncidentsResult> {
  const params: Record<string, string | number> = {
    limit: query.limit ?? 100,
    offset: query.offset ?? 0,
  };
  if (query.search) params.search = query.search;
  if (query.severity && query.severity !== "All") params.severity = query.severity;
  if (query.status) params.status = query.status;

  const { data } = await api.get<Page<ApiIncident>>("/incidents", { params });
  return { incidents: data.items.map(toUiIncident), total: data.total };
}

export async function fetchIncident(incidentId: string): Promise<Incident> {
  const { data } = await api.get<ApiIncident>(`/incidents/${incidentId}`);
  return toUiIncident(data);
}

export interface CreateIncidentInput {
  title: string;
  description?: string;
  severity?: Severity;
  source?: string;
  analyst?: string;
  eventIds?: string[];
  mitreTechniques?: string[];
}

export async function createIncident(input: CreateIncidentInput): Promise<Incident> {
  const { data } = await api.post<ApiIncident>("/incidents", input);
  return toUiIncident(data);
}

export interface UpdateIncidentInput {
  title?: string;
  description?: string;
  severity?: Severity;
  status?: IncidentStatus;
  analyst?: string;
  /** Why the status is changing. Required by the backend lifecycle for any
   *  transition that ends recorded work or undoes it. */
  statusReason?: string;
  /**
   * The evidence manifest the analyst actually reviewed.
   *
   * Sent on consequential transitions so the backend can refuse the decision
   * with 409 if the evidence moved between the page rendering and the click.
   * Omitting it is accepted and gets no protection.
   */
  expectedEvidenceDigest?: string;
}

export async function updateIncident(
  incidentId: string,
  input: UpdateIncidentInput,
): Promise<Incident> {
  const { data } = await api.patch<ApiIncident>(`/incidents/${incidentId}`, input);
  return toUiIncident(data);
}

/** Record (not execute) a response action against an incident. */
export async function recordResponseAction(
  incidentId: string,
  action: string,
): Promise<Incident> {
  const { data } = await api.post<ApiIncident>(`/incidents/${incidentId}/response`, {
    action,
  });
  return toUiIncident(data);
}
