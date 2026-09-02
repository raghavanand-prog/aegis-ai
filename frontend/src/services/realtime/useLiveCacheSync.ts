/**
 * Keeps the React Query cache in step with the WebSocket stream.
 *
 * Mounted once (in the dashboard layout) so every page benefits: an incident
 * created on the Events page shows up on the Incidents page without a reload,
 * and the notification badge updates wherever the analyst happens to be.
 *
 * Refetches are throttled. A busy SOC stream can deliver several events per
 * second, and one refetch per event would turn a push stream back into a
 * polling storm.
 */

import { useCallback, useEffect, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";

import type { RealtimeMessage } from "./socket";
import { useRealtimeMessages } from "./useRealtime";

const THROTTLE_MS = 4000;

export function useLiveCacheSync(enabled = true): void {
  const queryClient = useQueryClient();
  const pending = useRef<Set<string>>(new Set());
  const timer = useRef<number | null>(null);

  const flush = useCallback(() => {
    timer.current = null;
    const keys = Array.from(pending.current);
    pending.current.clear();
    keys.forEach((key) => {
      void queryClient.invalidateQueries({ queryKey: [key] });
    });
  }, [queryClient]);

  const schedule = useCallback(
    (...keys: string[]) => {
      keys.forEach((key) => pending.current.add(key));
      if (timer.current !== null) return;
      timer.current = window.setTimeout(flush, THROTTLE_MS);
    },
    [flush],
  );

  const handler = useCallback(
    (message: RealtimeMessage) => {
      switch (message.type) {
        case "event.created":
        case "event.updated":
          schedule("events", "analytics");
          break;

        case "incident.created":
        case "incident.updated":
          schedule("incidents", "analytics", "events");
          break;

        case "notification.created":
          schedule("notifications");
          break;

        default:
          break;
      }
    },
    [schedule],
  );

  useRealtimeMessages(handler, enabled);

  useEffect(
    () => () => {
      if (timer.current !== null) window.clearTimeout(timer.current);
    },
    [],
  );
}
