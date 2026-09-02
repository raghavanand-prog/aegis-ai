/** Correlated sequence endpoints. */

import { api } from "./client";
import type { ApiCorrelationPattern, ApiSequence } from "./mlTypes";
import type { ApiIncident } from "./types";

export interface SequenceQuery {
  status?: "Open" | "Promoted" | "Dismissed";
  severity?: string;
  pattern?: string;
  limit?: number;
  offset?: number;
}

export interface SequencesResult {
  items: ApiSequence[];
  total: number;
  limit: number;
  offset: number;
}

export async function fetchSequences(
  query: SequenceQuery = {},
): Promise<SequencesResult> {
  const params: Record<string, string | number> = {
    limit: query.limit ?? 50,
    offset: query.offset ?? 0,
  };
  if (query.status) params.status = query.status;
  if (query.severity && query.severity !== "All") params.severity = query.severity;
  if (query.pattern) params.pattern = query.pattern;

  const { data } = await api.get<SequencesResult>("/sequences", { params });
  return data;
}

export async function fetchSequence(sequenceId: string): Promise<ApiSequence> {
  const { data } = await api.get<ApiSequence>(`/sequences/${sequenceId}`);
  return data;
}

export async function fetchCorrelationPatterns(): Promise<{
  patterns: ApiCorrelationPattern[];
  engine: Record<string, unknown>;
}> {
  const { data } = await api.get<{
    patterns: ApiCorrelationPattern[];
    engine: Record<string, unknown>;
  }>("/sequences/patterns");
  return data;
}

/** Promote a sequence into an incident. Always an analyst decision. */
export async function promoteSequence(
  sequenceId: string,
  title?: string,
): Promise<{ sequence: ApiSequence; incident: ApiIncident }> {
  const { data } = await api.post<{ sequence: ApiSequence; incident: ApiIncident }>(
    `/sequences/${sequenceId}/promote`,
    title ? { title } : {},
  );
  return data;
}

export async function dismissSequence(sequenceId: string): Promise<ApiSequence> {
  const { data } = await api.post<ApiSequence>(`/sequences/${sequenceId}/dismiss`);
  return data;
}
