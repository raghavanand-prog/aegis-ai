/**
 * Detection engine transparency endpoints.
 *
 * These describe deterministic rules and their measured quality. Nothing here
 * is a model metric, and the payloads say so themselves.
 */

import { api } from "./client";
import type { ApiDetectionQuality, ApiRuleCatalogue } from "./types";

export async function fetchDetectionRules(): Promise<ApiRuleCatalogue> {
  const { data } = await api.get<ApiRuleCatalogue>("/detection/rules");
  return data;
}

/** Returns null when no evaluation has been run - callers must not invent numbers. */
export async function fetchDetectionQuality(): Promise<ApiDetectionQuality | null> {
  try {
    const { data } = await api.get<ApiDetectionQuality>("/detection/quality");
    return data;
  } catch (error) {
    if (error instanceof Error && "status" in error && (error as { status: number }).status === 404) {
      return null;
    }
    throw error;
  }
}

export async function runDetectionEvaluation(
  samplesPerClass = 60,
): Promise<ApiDetectionQuality> {
  const { data } = await api.post<ApiDetectionQuality>("/detection/quality/run", null, {
    params: { samplesPerClass },
  });
  return data;
}
