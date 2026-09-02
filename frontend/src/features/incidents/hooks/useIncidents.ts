/** React Query bindings for the incidents API. */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { queryKeys } from "@/lib/queryClient";
import {
  createIncident,
  fetchIncident,
  fetchIncidents,
  recordResponseAction,
  updateIncident,
  type CreateIncidentInput,
  type IncidentQuery,
  type UpdateIncidentInput,
} from "@/services/api/incidents";

export function useIncidentsQuery(filters: IncidentQuery = {}, enabled = true) {
  return useQuery({
    queryKey: queryKeys.incidents(filters),
    queryFn: () => fetchIncidents(filters),
    // Mounted above the router, so it must stay idle until there is a session.
    enabled,
  });
}

export function useIncidentQuery(incidentId: string | null) {
  return useQuery({
    queryKey: queryKeys.incident(incidentId ?? ""),
    queryFn: () => fetchIncident(incidentId as string),
    enabled: Boolean(incidentId),
  });
}

export function useCreateIncident() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (input: CreateIncidentInput) => createIncident(input),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["events"] });
      void queryClient.invalidateQueries({ queryKey: ["analytics"] });
    },
  });
}

export function useUpdateIncident() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      incidentId,
      input,
    }: {
      incidentId: string;
      input: UpdateIncidentInput;
    }) => updateIncident(incidentId, input),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["analytics"] });
    },
  });
}

export function useRecordResponseAction() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ incidentId, action }: { incidentId: string; action: string }) =>
      recordResponseAction(incidentId, action),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["notifications"] });
    },
  });
}
