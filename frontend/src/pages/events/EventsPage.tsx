import { useCallback, useMemo, useState } from "react";

import EventHeader from "../../features/events/components/EventHeader";
import EventStats from "../../features/events/components/EventStats";
import EventFilters from "../../features/events/components/EventFilters";
import EventTable from "../../features/events/components/EventTable";
import EventDetailsDrawer from "../../features/events/components/EventDetailsDrawer";
import LiveEventBanner from "../../features/events/components/LiveEventBanner";

import type { Event } from "../../features/events/types";
import { useEventsQuery, usePromoteEvent } from "../../features/events/hooks/useEvents";
import { usePermissions } from "../../features/auth/hooks/usePermissions";

import { EmptyState, ErrorState, LoadingState } from "@/components/ui";
import { toUiEvent } from "@/services/api/events";
import type { ApiEvent, Severity } from "@/services/api/types";
import type { RealtimeMessage } from "@/services/realtime/socket";
import {
  useRealtimeMessages,
  useRealtimeStatus,
} from "@/services/realtime/useRealtime";

/** Cap the in-memory live buffer so a long session cannot grow without bound. */
const MAX_LIVE_EVENTS = 200;

export default function EventsPage() {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("All");

  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Events that arrived over the WebSocket since the last fetch, held
  // separately so the table updates the moment telemetry lands instead of
  // waiting for a refetch. The buffer is tagged with the filters it was
  // captured under, so changing a filter discards it without an effect.
  const filterKey = `${search.trim().toLowerCase()}|${severity}`;
  const [liveBuffer, setLiveBuffer] = useState<{ key: string; events: Event[] }>({
    key: filterKey,
    events: [],
  });
  const liveEvents = useMemo(
    () => (liveBuffer.key === filterKey ? liveBuffer.events : []),
    [liveBuffer, filterKey],
  );

  const filters = useMemo(
    () => ({
      search: search.trim() || undefined,
      severity: severity as Severity | "All",
      limit: 100,
    }),
    [search, severity],
  );

  const eventsQuery = useEventsQuery(filters);
  const promoteMutation = usePromoteEvent();
  const { canPromoteEvents } = usePermissions();
  const connectionStatus = useRealtimeStatus();

  const matchesFilters = useCallback(
    (event: Event) => {
      const term = search.trim().toLowerCase();
      const matchesSearch =
        !term ||
        event.source.toLowerCase().includes(term) ||
        event.event.toLowerCase().includes(term) ||
        event.id.toLowerCase().includes(term) ||
        (event.hostname ?? "").toLowerCase().includes(term) ||
        (event.username ?? "").toLowerCase().includes(term);

      const matchesSeverity = severity === "All" || event.severity === severity;
      return matchesSearch && matchesSeverity;
    },
    [search, severity],
  );

  const handleStreamMessage = useCallback(
    (message: RealtimeMessage) => {
      if (message.type !== "event.created") return;

      const incoming = toUiEvent(message.data as ApiEvent);
      if (!matchesFilters(incoming)) return;

      setLiveBuffer((current) => {
        const existing = current.key === filterKey ? current.events : [];
        return {
          key: filterKey,
          events: [
            incoming,
            ...existing.filter((event) => event.id !== incoming.id),
          ].slice(0, MAX_LIVE_EVENTS),
        };
      });
    },
    [matchesFilters, filterKey],
  );

  useRealtimeMessages(handleStreamMessage);

  // Live arrivals sit on top; anything already returned by the API is not
  // duplicated.
  const events = useMemo(() => {
    const fetched = eventsQuery.data?.events ?? [];
    const seen = new Set(liveEvents.map((event) => event.id));
    return [...liveEvents, ...fetched.filter((event) => !seen.has(event.id))];
  }, [eventsQuery.data, liveEvents]);

  const openEvent = (event: Event) => {
    setSelectedEvent(event);
    setDrawerOpen(true);
  };

  const closeDrawer = () => {
    setDrawerOpen(false);
    setSelectedEvent(null);
  };

  const promoteEvent = async (event: Event) => {
    if (event.incidentId || !canPromoteEvents) return;
    try {
      await promoteMutation.mutateAsync({ eventId: event.id });
      setLiveBuffer((current) => ({
        key: current.key,
        events: current.events.map((item) =>
          item.id === event.id
            ? { ...item, status: "Investigating" as const }
            : item,
        ),
      }));
      closeDrawer();
    } catch {
      // Surfaced through promoteMutation.error below.
    }
  };

  const isInitialLoad = eventsQuery.isLoading && liveEvents.length === 0;

  return (
    <div className="space-y-8">
      <EventHeader />

      <LiveEventBanner
        totalEvents={eventsQuery.data?.total ?? events.length}
        connectionStatus={connectionStatus}
        liveCount={liveEvents.length}
      />

      {promoteMutation.isError && (
        <ErrorState
          error={promoteMutation.error}
          title="Could not promote the event"
          onRetry={() => promoteMutation.reset()}
        />
      )}

      <EventStats events={events} />

      <EventFilters
        search={search}
        setSearch={setSearch}
        severity={severity}
        setSeverity={setSeverity}
      />

      {isInitialLoad ? (
        <LoadingState label="Loading events from the telemetry pipeline..." />
      ) : eventsQuery.isError && events.length === 0 ? (
        <ErrorState error={eventsQuery.error} onRetry={() => void eventsQuery.refetch()} />
      ) : events.length === 0 ? (
        <EmptyState
          title="No events match this view"
          description={
            search || severity !== "All"
              ? "Try widening the search or severity filter."
              : "Waiting for the telemetry collector to produce its first event."
          }
        />
      ) : (
        <EventTable
          events={events}
          onEventClick={openEvent}
          onPromote={promoteEvent}
          canPromote={canPromoteEvents}
        />
      )}

      <EventDetailsDrawer
        event={selectedEvent}
        open={drawerOpen}
        onClose={closeDrawer}
        onPromote={canPromoteEvents ? promoteEvent : undefined}
        isPromoting={promoteMutation.isPending}
      />
    </div>
  );
}
