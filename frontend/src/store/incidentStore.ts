/**
 * Incident store context and hook.
 *
 * Separated from the provider component so that file only exports components.
 */

import { createContext, useContext } from "react";

import type { Incident } from "@/features/incidents/types";

export interface IncidentContextType {
  incidents: Incident[];
  total: number;
  isLoading: boolean;
  isError: boolean;
  error: unknown;
  refetch: () => void;
  /** Optimistically place an incident at the top of the cached list. */
  addIncident: (incident: Incident) => void;
}

export const IncidentContext = createContext<IncidentContextType | null>(null);

export function useIncidentsStore(): IncidentContextType {
  const context = useContext(IncidentContext);

  if (!context) {
    throw new Error("useIncidentsStore must be used inside IncidentProvider");
  }

  return context;
}
