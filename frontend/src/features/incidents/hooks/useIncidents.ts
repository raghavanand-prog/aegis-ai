/** React Query bindings for the incidents API. */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { queryKeys } from "@/lib/queryClient";
import type { ApiEvidenceSet } from "@/services/api/evidence";
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

/**
 * Statuses whose transition the backend binds evidence to.
 *
 * Duplicated from `app/incidents/lifecycle.py` deliberately, and safe to
 * duplicate because the duplication cannot grant anything. Being wrong in one
 * direction sends a digest the backend ignores; being wrong in the other sends
 * none, which is exactly today's behaviour. The backend decides what is
 * consequential and re-checks everything; this list only decides whether the
 * client opts into the protection.
 */
const EVIDENCE_BOUND_STATUSES = new Set([
  "Containment Pending",
  "Contained",
  "Resolved",
  "Closed",
]);

export function useUpdateIncident() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      incidentId,
      input,
    }: {
      incidentId: string;
      input: UpdateIncidentInput;
    }) => {
      // V9: state which evidence this decision was taken on.
      //
      // Attached here rather than at each call site so a consequential
      // transition cannot be made without it by someone forgetting. The digest
      // is the one the workspace actually rendered — read from the cache the
      // evidence panel populated — so a 409 means precisely "the evidence
      // moved between you reading it and clicking", which is the window this
      // closes. With no cached evidence there is nothing to claim to have
      // reviewed, and the request goes without it.
      let payload = input;
      if (
        input.status &&
        input.expectedEvidenceDigest === undefined &&
        EVIDENCE_BOUND_STATUSES.has(input.status)
      ) {
        const evidence = queryClient.getQueryData<ApiEvidenceSet>([
          "incident",
          incidentId,
          "evidence",
        ]);
        if (evidence?.manifestDigest) {
          payload = { ...input, expectedEvidenceDigest: evidence.manifestDigest };
        }
      }
      return updateIncident(incidentId, payload);
    },
    onSuccess: (_data, variables) => {
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["analytics"] });
      // The decision list and the evidence behind it both move on a
      // consequential transition; a stale panel would show the previous
      // decision's verdict against the new state.
      void queryClient.invalidateQueries({
        queryKey: ["incident", variables.incidentId],
      });
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
