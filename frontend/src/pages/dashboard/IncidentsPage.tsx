import { useState } from "react";

import IncidentHeader from "../../features/incidents/components/IncidentHeader";
import IncidentStats from "../../features/incidents/components/IncidentStats";
import IncidentFilters from "../../features/incidents/components/IncidentFilters";
import IncidentList from "../../features/incidents/components/IncidentList";
import InvestigationWorkspace from "../../features/incidents/components/workspace/InvestigationWorkspace";

import type { Incident } from "../../features/incidents/types";

import { useIncidentsStore } from "../../store/incidentStore";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui";

export default function IncidentsPage() {
  const { incidents, isLoading, isError, error, refetch } = useIncidentsStore();

  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const openIncident = (incident: Incident) => {
    setSelectedIncident(incident);
    setDrawerOpen(true);
  };

  const closeDrawer = () => {
    setDrawerOpen(false);
    setSelectedIncident(null);
  };

  return (
    <>
      <div className="space-y-8">
        <IncidentHeader />

        <IncidentStats incidents={incidents} />

        <IncidentFilters />

        {isLoading ? (
          <LoadingState label="Loading incidents..." />
        ) : isError ? (
          <ErrorState error={error} onRetry={refetch} />
        ) : incidents.length === 0 ? (
          <EmptyState
            title="No incidents yet"
            description="Promote an event from the Events page to open the first incident."
          />
        ) : (
          <IncidentList incidents={incidents} onIncidentClick={openIncident} />
        )}
      </div>

      {/* V3: the workspace fetches the incident itself, so it only needs the
          identifier. The list row it was opened from may be a stale summary. */}
      <InvestigationWorkspace
        incidentId={selectedIncident?.id ?? null}
        open={drawerOpen}
        onClose={closeDrawer}
      />
    </>
  );
}
