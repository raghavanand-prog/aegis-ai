/** Shared React Query client. */

import { QueryClient } from "@tanstack/react-query";

import { ApiError } from "@/services/api/client";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // The WebSocket stream pushes updates, so aggressive refetching is
      // unnecessary; a short stale window keeps manual refreshes cheap.
      staleTime: 10_000,
      refetchOnWindowFocus: false,
      retry: (failureCount, error) => {
        // Never retry auth failures - the token is gone, not flaky.
        if (error instanceof ApiError && error.isAuthError) return false;
        return failureCount < 2;
      },
    },
    mutations: { retry: false },
  },
});

/** Query keys in one place so invalidation cannot drift from fetching. */
export const queryKeys = {
  events: (filters?: unknown) => ["events", filters ?? {}] as const,
  event: (id: string) => ["event", id] as const,
  incidents: (filters?: unknown) => ["incidents", filters ?? {}] as const,
  incident: (id: string) => ["incident", id] as const,
  notifications: () => ["notifications"] as const,
  notificationCounts: () => ["notifications", "counts"] as const,
  analytics: (windowHours: number) => ["analytics", windowHours] as const,
  telemetryStatus: () => ["telemetry", "status"] as const,
  iocs: (filters?: unknown) => ["iocs", filters ?? {}] as const,
} as const;
