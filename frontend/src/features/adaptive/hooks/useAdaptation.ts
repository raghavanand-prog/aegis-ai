/** React Query bindings for the controlled adaptation API (V5). */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  approveProposal,
  deployProposal,
  fetchDriftStatus,
  fetchFeedback,
  fetchFeedbackDatasets,
  fetchProposals,
  fetchReviewQueue,
  rejectProposal,
  rollbackProposal,
} from "@/services/api/adaptation";

export function useFeedback(limit = 100) {
  return useQuery({
    queryKey: ["adaptation", "feedback", limit] as const,
    queryFn: () => fetchFeedback({ limit }),
  });
}

export function useDriftStatus() {
  return useQuery({
    queryKey: ["adaptation", "drift"] as const,
    queryFn: fetchDriftStatus,
  });
}

export function useReviewQueue(limit = 25) {
  return useQuery({
    queryKey: ["adaptation", "review-queue", limit] as const,
    queryFn: () => fetchReviewQueue(limit),
  });
}

export function useFeedbackDatasets() {
  return useQuery({
    queryKey: ["adaptation", "datasets"] as const,
    queryFn: fetchFeedbackDatasets,
  });
}

export function useProposals() {
  return useQuery({
    queryKey: ["adaptation", "proposals"] as const,
    queryFn: () => fetchProposals(),
  });
}

/**
 * Approval, rejection, deployment and rollback.
 *
 * Each invalidates the proposal list rather than patching it locally: the
 * server decides what a transition produced, and a client that guesses can show
 * an adaptation as deployed when it was refused.
 */
export function useProposalActions() {
  const queryClient = useQueryClient();
  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["adaptation", "proposals"] });
  };

  return {
    approve: useMutation({ mutationFn: approveProposal, onSuccess: invalidate }),
    reject: useMutation({
      mutationFn: ({ id, reason }: { id: number; reason: string }) => rejectProposal(id, reason),
      onSuccess: invalidate,
    }),
    deploy: useMutation({ mutationFn: deployProposal, onSuccess: invalidate }),
    rollback: useMutation({
      mutationFn: ({ id, reason }: { id: number; reason: string }) => rollbackProposal(id, reason),
      onSuccess: invalidate,
    }),
  };
}
