/** React Query bindings for backend analytics aggregation. */

import { useQuery } from "@tanstack/react-query";

import { queryKeys } from "@/lib/queryClient";
import { fetchAnalyticsSummary, fetchTelemetryStatus } from "@/services/api/analytics";

export function useAnalyticsSummary(windowHours = 24) {
  return useQuery({
    queryKey: queryKeys.analytics(windowHours),
    queryFn: () => fetchAnalyticsSummary(windowHours),
  });
}

export function useTelemetryStatus() {
  return useQuery({
    queryKey: queryKeys.telemetryStatus(),
    queryFn: fetchTelemetryStatus,
    refetchInterval: 15_000,
  });
}
