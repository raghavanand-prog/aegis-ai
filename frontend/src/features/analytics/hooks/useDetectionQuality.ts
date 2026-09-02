/** React Query bindings for detection engine transparency. */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  fetchDetectionQuality,
  fetchDetectionRules,
  runDetectionEvaluation,
} from "@/services/api/detection";

export function useDetectionQuality() {
  return useQuery({
    queryKey: ["detection", "quality"],
    queryFn: fetchDetectionQuality,
    // A missing report is a valid answer ("nothing measured yet"), not an error.
    retry: 1,
  });
}

export function useDetectionRules(enabled = true) {
  return useQuery({
    queryKey: ["detection", "rules"],
    queryFn: fetchDetectionRules,
    enabled,
    staleTime: 5 * 60 * 1000,
  });
}

export function useRunDetectionEvaluation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (samplesPerClass?: number) => runDetectionEvaluation(samplesPerClass),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["detection"] });
    },
  });
}
