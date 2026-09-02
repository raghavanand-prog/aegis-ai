/**
 * Notification shape rendered by the drawer.
 *
 * Notifications come from the backend (`GET /notifications`); the static demo
 * list this file used to export was removed when the API was wired up.
 */

export interface Notification {
  id: number;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  time: string;

  /** Enriched fields supplied by the backend. */
  category?: "event" | "incident" | "assignment" | "response" | "system";
  isRead?: boolean;
  eventId?: string | null;
  incidentId?: string | null;
  createdAt?: string;
}
