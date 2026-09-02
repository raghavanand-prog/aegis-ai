/** React Query bindings for the events API. */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { queryKeys } from "@/lib/queryClient";
import {
  fetchEvent,
  fetchEvents,
  promoteEvent,
  updateEventStatus,
  type EventQuery,
  type PromoteOptions,
} from "@/services/api/events";
import type { EventStatus } from "@/services/api/types";

export function useEventsQuery(filters: EventQuery = {}) {
  return useQuery({
    queryKey: queryKeys.events(filters),
    queryFn: () => fetchEvents(filters),
  });
}

export function useEventQuery(eventId: string | null) {
  return useQuery({
    queryKey: queryKeys.event(eventId ?? ""),
    queryFn: () => fetchEvent(eventId as string),
    enabled: Boolean(eventId),
  });
}

/** Promote an event into an incident, then refresh everything it touches. */
export function usePromoteEvent() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      eventId,
      options,
    }: {
      eventId: string;
      options?: PromoteOptions;
    }) => promoteEvent(eventId, options),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["events"] });
      void queryClient.invalidateQueries({ queryKey: ["analytics"] });
      void queryClient.invalidateQueries({ queryKey: ["notifications"] });
    },
  });
}

export function useUpdateEventStatus() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ eventId, status }: { eventId: string; status: EventStatus }) =>
      updateEventStatus(eventId, status),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["events"] });
      void queryClient.invalidateQueries({ queryKey: ["analytics"] });
    },
  });
}
