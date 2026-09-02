/** Machine learning endpoints. */

import { api } from "./client";
import type {
  ApiEventMLFindings,
  ApiMLModel,
  ApiMLModelList,
  ApiMLStatus,
  ApiScoringStrategy,
} from "./mlTypes";

export async function fetchMLStatus(): Promise<ApiMLStatus> {
  const { data } = await api.get<ApiMLStatus>("/ml/status");
  return data;
}

export async function fetchMLModels(): Promise<ApiMLModelList> {
  const { data } = await api.get<ApiMLModelList>("/ml/models");
  return data;
}

export async function fetchScoringStrategy(): Promise<ApiScoringStrategy> {
  const { data } = await api.get<ApiScoringStrategy>("/ml/scoring");
  return data;
}

/**
 * ML findings for one event.
 *
 * An empty `findings` array does NOT mean "nothing was anomalous" - it can also
 * mean the model never scored this event. `modelAvailable` and `reason` are what
 * tell the two apart, and every caller must render them.
 */
export async function fetchEventMLFindings(
  eventId: string,
): Promise<ApiEventMLFindings> {
  const { data } = await api.get<ApiEventMLFindings>(`/ml/events/${eventId}`);
  return data;
}

export interface IncidentMLFindings {
  incidentId: string;
  modelAvailable: boolean;
  reason: string | null;
  eventsScored: number;
  anomalyCount: number;
  findings: Array<{
    eventId: string;
    eventTitle: string;
    model: string;
    modelVersion: string;
    anomalyScore: number;
    scoreKind: string;
    isAnomaly: boolean;
    threshold: number;
    topContributors: { name: string; value: number; deviation: number; direction: string }[];
    inferredAt: string;
  }>;
}

export async function fetchIncidentMLFindings(
  incidentId: string,
): Promise<IncidentMLFindings> {
  const { data } = await api.get<IncidentMLFindings>(`/ml/incidents/${incidentId}`);
  return data;
}

export async function activateModel(modelId: number): Promise<ApiMLModel> {
  const { data } = await api.post<{ model: ApiMLModel }>(`/ml/models/${modelId}/activate`);
  return data.model;
}

export async function deactivateModel(modelId: number): Promise<ApiMLModel> {
  const { data } = await api.post<{ model: ApiMLModel }>(`/ml/models/${modelId}/deactivate`);
  return data.model;
}

export async function rollbackModel(name = "isolation_forest"): Promise<ApiMLModel> {
  const { data } = await api.post<{ model: ApiMLModel }>("/ml/models/rollback", null, {
    params: { name },
  });
  return data.model;
}
