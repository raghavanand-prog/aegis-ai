/** Notification endpoints. */

import type { Notification } from "@/features/notifications/notifications";
import { relativeTime } from "@/lib/time";

import { api } from "./client";
import type { ApiNotification, ApiNotificationCounts, Page } from "./types";

export function toUiNotification(dto: ApiNotification): Notification {
  return {
    id: dto.id,
    severity: dto.severity,
    title: dto.title,
    description: dto.description,
    time: relativeTime(dto.createdAt),
    category: dto.category,
    isRead: dto.isRead,
    eventId: dto.eventId,
    incidentId: dto.incidentId,
    createdAt: dto.createdAt,
  };
}

export async function fetchNotifications(limit = 50): Promise<Notification[]> {
  const { data } = await api.get<Page<ApiNotification>>("/notifications", {
    params: { limit },
  });
  return data.items.map(toUiNotification);
}

export async function fetchNotificationCounts(): Promise<ApiNotificationCounts> {
  const { data } = await api.get<ApiNotificationCounts>("/notifications/counts");
  return data;
}

export async function markNotificationRead(id: number): Promise<Notification> {
  const { data } = await api.post<ApiNotification>(`/notifications/${id}/read`);
  return toUiNotification(data);
}

export async function markAllNotificationsRead(): Promise<ApiNotificationCounts> {
  const { data } = await api.post<ApiNotificationCounts>("/notifications/read-all");
  return data;
}
