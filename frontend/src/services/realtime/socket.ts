/**
 * WebSocket client for the AEGISX live stream.
 *
 * One shared connection is used by the whole app. It reconnects with
 * exponential backoff plus jitter, and a watchdog forces a reconnect when the
 * server's heartbeat stops arriving - a socket can stay "open" long after the
 * backend has gone away, so silence is treated as a failure.
 */

import { API_BASE_URL } from "@/services/api/client";
import { getToken } from "@/services/api/tokenStore";

export type ConnectionStatus =
  | "idle"
  | "connecting"
  | "connected"
  | "reconnecting"
  | "disconnected"
  | "unauthorized";

export type RealtimeMessageType =
  | "connection.ack"
  | "event.created"
  | "event.updated"
  | "incident.created"
  | "incident.updated"
  | "notification.created"
  | "heartbeat"
  | "pong";

export interface RealtimeMessage<T = unknown> {
  type: RealtimeMessageType;
  data: T;
  ts?: string;
}

type MessageHandler = (message: RealtimeMessage) => void;
type StatusHandler = (status: ConnectionStatus) => void;

const INITIAL_RETRY_MS = 1000;
const MAX_RETRY_MS = 30000;
/** Server heartbeat is 25s; miss two and we assume the link is dead. */
const WATCHDOG_MS = 60000;

function buildStreamUrl(token: string): string {
  const base = API_BASE_URL.replace(/^http/, "ws");
  return `${base}/ws/stream?token=${encodeURIComponent(token)}`;
}

class RealtimeClient {
  private socket: WebSocket | null = null;
  private status: ConnectionStatus = "idle";
  private retryDelay = INITIAL_RETRY_MS;
  private retryTimer: number | null = null;
  private watchdogTimer: number | null = null;
  private shouldRun = false;

  private readonly messageHandlers = new Set<MessageHandler>();
  private readonly statusHandlers = new Set<StatusHandler>();

  getStatus(): ConnectionStatus {
    return this.status;
  }

  onMessage(handler: MessageHandler): () => void {
    this.messageHandlers.add(handler);
    return () => this.messageHandlers.delete(handler);
  }

  onStatus(handler: StatusHandler): () => void {
    this.statusHandlers.add(handler);
    handler(this.status);
    return () => this.statusHandlers.delete(handler);
  }

  /** Open the stream. Safe to call repeatedly. */
  start(): void {
    this.shouldRun = true;
    if (this.socket && this.socket.readyState <= WebSocket.OPEN) return;
    this.open();
  }

  /** Close the stream and stop reconnecting. */
  stop(): void {
    this.shouldRun = false;
    this.clearTimers();
    if (this.socket) {
      this.socket.onclose = null;
      this.socket.close();
      this.socket = null;
    }
    this.setStatus("disconnected");
  }

  private setStatus(status: ConnectionStatus): void {
    if (this.status === status) return;
    this.status = status;
    this.statusHandlers.forEach((handler) => handler(status));
  }

  private clearTimers(): void {
    if (this.retryTimer !== null) {
      window.clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    if (this.watchdogTimer !== null) {
      window.clearTimeout(this.watchdogTimer);
      this.watchdogTimer = null;
    }
  }

  private pokeWatchdog(): void {
    if (this.watchdogTimer !== null) window.clearTimeout(this.watchdogTimer);
    this.watchdogTimer = window.setTimeout(() => {
      // Nothing heard for a full watchdog window: treat the socket as dead.
      this.socket?.close();
    }, WATCHDOG_MS);
  }

  private open(): void {
    const token = getToken();
    if (!token) {
      this.setStatus("unauthorized");
      return;
    }

    this.setStatus(this.retryDelay === INITIAL_RETRY_MS ? "connecting" : "reconnecting");

    let socket: WebSocket;
    try {
      socket = new WebSocket(buildStreamUrl(token));
    } catch {
      this.scheduleReconnect();
      return;
    }
    this.socket = socket;

    socket.onopen = () => {
      this.retryDelay = INITIAL_RETRY_MS;
      this.setStatus("connected");
      this.pokeWatchdog();
    };

    socket.onmessage = (raw) => {
      this.pokeWatchdog();
      try {
        const message = JSON.parse(raw.data as string) as RealtimeMessage;
        this.messageHandlers.forEach((handler) => handler(message));
      } catch {
        // A malformed frame is dropped rather than killing the stream.
      }
    };

    socket.onerror = () => {
      // onclose always follows; reconnection is handled there.
    };

    socket.onclose = (closeEvent) => {
      this.socket = null;
      this.clearTimers();

      // 4401 is the backend's "invalid or missing token" code - retrying with
      // the same token would just loop, so the user has to sign in again.
      if (closeEvent.code === 4401) {
        this.setStatus("unauthorized");
        return;
      }

      if (!this.shouldRun) {
        this.setStatus("disconnected");
        return;
      }

      this.setStatus("reconnecting");
      this.scheduleReconnect();
    };
  }

  private scheduleReconnect(): void {
    if (!this.shouldRun) return;

    const jitter = Math.random() * 300;
    const delay = Math.min(this.retryDelay, MAX_RETRY_MS) + jitter;
    this.retryTimer = window.setTimeout(() => this.open(), delay);
    this.retryDelay = Math.min(this.retryDelay * 2, MAX_RETRY_MS);
  }
}

export const realtime = new RealtimeClient();
