/** Analytics endpoints. */

import { api } from "./client";
import type { ApiAnalyticsSummary, ApiTelemetryStatus } from "./types";

export async function fetchAnalyticsSummary(
  windowHours = 24,
): Promise<ApiAnalyticsSummary> {
  const { data } = await api.get<ApiAnalyticsSummary>("/analytics/summary", {
    params: { windowHours },
  });
  return data;
}

export async function fetchTelemetryStatus(): Promise<ApiTelemetryStatus> {
  const { data } = await api.get<ApiTelemetryStatus>("/telemetry/status");
  return data;
}
