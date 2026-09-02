/**
 * Incident store.
 *
 * Incidents live in PostgreSQL and are fetched through the API; this context
 * is now only a thin cache/UI layer over React Query so existing components
 * that call `useIncidentsStore()` keep working unchanged. Nothing persistent
 * is held in React state any more - a reload no longer loses incidents, and
 * two analysts see the same list.
 */

import { useCallback, useMemo, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { useAuth } from "@/features/auth/hooks/useAuth";
import { useIncidentsQuery } from "@/features/incidents/hooks/useIncidents";
import type { Incident } from "@/features/incidents/types";

import { IncidentContext, type IncidentContextType } from "./incidentStore";

export function IncidentProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const { isAuthenticated } = useAuth();
  const query = useIncidentsQuery({ limit: 100 }, isAuthenticated);

  const addIncident = useCallback(
    (incident: Incident) => {
      queryClient.setQueriesData<{ incidents: Incident[]; total: number }>(
        { queryKey: ["incidents"] },
        (current) =>
          current
            ? {
                incidents: [
                  incident,
                  ...current.incidents.filter((item) => item.id !== incident.id),
                ],
                total: current.total + 1,
              }
            : { incidents: [incident], total: 1 },
      );
    },
    [queryClient],
  );

  const value = useMemo<IncidentContextType>(
    () => ({
      incidents: query.data?.incidents ?? [],
      total: query.data?.total ?? 0,
      isLoading: query.isLoading,
      isError: query.isError,
      error: query.error,
      refetch: () => void query.refetch(),
      addIncident,
    }),
    [query, addIncident],
  );

  return (
    <IncidentContext.Provider value={value}>{children}</IncidentContext.Provider>
  );
}
