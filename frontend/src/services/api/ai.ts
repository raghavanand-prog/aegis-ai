/**
 * AI analyst endpoints.
 *
 * The frontend never holds a provider key and never calls a provider. It asks
 * the AEGISX backend, which holds the credential server-side.
 */

import { api } from "./client";
import type { ApiAIAnalysis, ApiAIAnalysisList, ApiAIStatus } from "./mlTypes";

export type AIAnalysisKind = "analyze" | "explain" | "recommend";

export async function fetchAIStatus(): Promise<ApiAIStatus> {
  const { data } = await api.get<ApiAIStatus>("/ai/status");
  return data;
}

export async function fetchAIAnalyses(incidentId: string): Promise<ApiAIAnalysisList> {
  const { data } = await api.get<ApiAIAnalysisList>(
    `/ai/incidents/${incidentId}/analyses`,
  );
  return data;
}

/**
 * Request a fresh analysis.
 *
 * Throws an ApiError with status 503 when the analyst is unavailable - the
 * caller renders that reason rather than an error, because an unconfigured AI
 * provider is a degraded state, not a failure.
 */
export async function requestAIAnalysis(
  incidentId: string,
  kind: AIAnalysisKind,
  question?: string,
): Promise<ApiAIAnalysis> {
  const { data } = await api.post<ApiAIAnalysis>(
    `/ai/incidents/${incidentId}/${kind}`,
    question ? { question } : {},
  );
  return data;
}

export interface AIEvidencePreview {
  incidentId: string;
  fingerprint: string;
  summary: Record<string, number>;
  sufficient: boolean;
  injectionAttemptsDetected: string[];
  package: Record<string, unknown>;
}

/** Exactly what would be sent to a provider. Calls no provider, stores nothing. */
export async function fetchAIEvidence(incidentId: string): Promise<AIEvidencePreview> {
  const { data } = await api.get<AIEvidencePreview>(
    `/ai/incidents/${incidentId}/evidence`,
  );
  return data;
}
