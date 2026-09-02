/**
 * Threat intelligence endpoints.
 *
 * API keys live on the AEGISX server. Nothing in this module carries one, and
 * the browser never talks to a reputation provider directly.
 */

import { api, ApiError } from "./client";
import type { ApiThreatIntel, ApiThreatIntelStatus } from "./mlTypes";

export async function fetchThreatIntelStatus(): Promise<ApiThreatIntelStatus> {
  const { data } = await api.get<ApiThreatIntelStatus>("/threat-intel/status");
  return data;
}

export interface ThreatIntelListResult {
  results: ApiThreatIntel[];
  total: number;
  status: ApiThreatIntelStatus;
}

export async function fetchThreatIntelResults(
  limit = 50,
): Promise<ThreatIntelListResult> {
  const { data } = await api.get<ThreatIntelListResult>("/threat-intel", {
    params: { limit },
  });
  return data;
}

export interface IndicatorIntel {
  results: ApiThreatIntel[];
  /**
   * Set when AEGISX will never look this indicator up externally - an internal
   * address, a documentation range, an unsupported type. Distinct from "no
   * verdict yet", and rendered as such.
   */
  notLookedUp: string | null;
}

/** Cached verdicts for one indicator. Never throws for an ordinary miss. */
export async function fetchIndicatorIntel(
  value: string,
  type = "ip",
): Promise<IndicatorIntel> {
  try {
    const { data } = await api.get<IndicatorIntel>(
      `/threat-intel/ioc/${encodeURIComponent(value)}`,
      { params: { type } },
    );
    return { results: data.results ?? [], notLookedUp: data.notLookedUp ?? null };
  } catch (error) {
    // 404 means "nothing looked up yet", which is a normal state, not an error.
    if (error instanceof ApiError && error.status === 404) {
      return { results: [], notLookedUp: null };
    }
    throw error;
  }
}

/** Trigger a live lookup. Analyst role required; reaches outside the estate. */
export async function enrichIndicator(
  value: string,
  type = "ip",
  force = false,
): Promise<ApiThreatIntel> {
  const { data } = await api.post<ApiThreatIntel>(
    `/threat-intel/ioc/${encodeURIComponent(value)}/enrich`,
    null,
    { params: { type, force } },
  );
  return data;
}
