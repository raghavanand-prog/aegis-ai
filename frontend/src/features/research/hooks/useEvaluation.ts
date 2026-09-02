/** React Query bindings for the research evaluation API. */

import { useQuery } from "@tanstack/react-query";

import {
  fetchDatasets,
  fetchEvaluationStatus,
  fetchExperiment,
  fetchExperiments,
} from "@/services/api/evaluation";

export function useEvaluationStatus() {
  return useQuery({
    queryKey: ["evaluation", "status"] as const,
    queryFn: fetchEvaluationStatus,
  });
}

export function useExperiments(filters: { dataset?: string; split?: string } = {}) {
  return useQuery({
    queryKey: ["evaluation", "experiments", filters] as const,
    queryFn: () => fetchExperiments(filters),
  });
}

export function useExperiment(experimentId: string | null) {
  return useQuery({
    queryKey: ["evaluation", "experiment", experimentId] as const,
    queryFn: () => fetchExperiment(experimentId as string),
    enabled: Boolean(experimentId),
  });
}

export function useEvaluationDatasets() {
  return useQuery({
    queryKey: ["evaluation", "datasets"] as const,
    queryFn: fetchDatasets,
  });
}
