/**
 * React bindings for the live stream.
 *
 * `useRealtimeStatus` exposes the connection state so pages can show whether
 * telemetry is flowing. `useRealtimeMessages` subscribes to stream events and
 * keeps the React Query cache in sync, so lists update live without polling.
 */

import { useEffect, useState } from "react";

import type { ConnectionStatus, RealtimeMessage } from "./socket";
import { realtime } from "./socket";

export function useRealtimeStatus(enabled = true): ConnectionStatus {
  const [status, setStatus] = useState<ConnectionStatus>(realtime.getStatus());

  useEffect(() => {
    if (!enabled) return;

    const unsubscribe = realtime.onStatus(setStatus);
    realtime.start();
    return unsubscribe;
  }, [enabled]);

  return status;
}

export function useRealtimeMessages(
  handler: (message: RealtimeMessage) => void,
  enabled = true,
): void {
  useEffect(() => {
    if (!enabled) return;

    const unsubscribe = realtime.onMessage(handler);
    realtime.start();
    return unsubscribe;
  }, [handler, enabled]);
}

export function isStreamHealthy(status: ConnectionStatus): boolean {
  return status === "connected";
}
