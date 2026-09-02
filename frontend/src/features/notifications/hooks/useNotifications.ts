/** React Query bindings for notifications. */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { queryKeys } from "@/lib/queryClient";
import {
  fetchNotificationCounts,
  fetchNotifications,
  markAllNotificationsRead,
  markNotificationRead,
} from "@/services/api/notifications";

export function useNotificationsQuery(enabled = true) {
  return useQuery({
    queryKey: queryKeys.notifications(),
    queryFn: () => fetchNotifications(50),
    enabled,
  });
}

export function useNotificationCounts(enabled = true) {
  return useQuery({
    queryKey: queryKeys.notificationCounts(),
    queryFn: fetchNotificationCounts,
    enabled,
  });
}

export function useMarkNotificationRead() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: number) => markNotificationRead(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["notifications"] });
    },
  });
}

export function useMarkAllNotificationsRead() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: markAllNotificationsRead,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["notifications"] });
    },
  });
}
