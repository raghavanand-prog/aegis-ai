import { Radio, RefreshCw, WifiOff } from "lucide-react";

import type { ConnectionStatus } from "@/services/realtime/socket";

interface Props {
  totalEvents: number;
  connectionStatus?: ConnectionStatus;
  liveCount?: number;
}

const PRESENTATION: Record<
  ConnectionStatus,
  { label: string; detail: string; tone: string; icon: typeof Radio; pulse: boolean }
> = {
  connected: {
    label: "Live Event Stream",
    detail: "Monitoring incoming security telemetry...",
    tone: "border-cyan-500/20 bg-cyan-500/10 text-cyan-400",
    icon: Radio,
    pulse: true,
  },
  connecting: {
    label: "Connecting to telemetry stream",
    detail: "Opening the live channel to the AEGISX backend...",
    tone: "border-slate-600/30 bg-slate-700/10 text-slate-300",
    icon: RefreshCw,
    pulse: true,
  },
  reconnecting: {
    label: "Reconnecting to telemetry stream",
    detail: "The live channel dropped. Retrying with backoff - shown events may be stale.",
    tone: "border-amber-500/25 bg-amber-500/10 text-amber-400",
    icon: RefreshCw,
    pulse: true,
  },
  disconnected: {
    label: "Telemetry stream disconnected",
    detail: "No live channel. Events shown are from the last successful load.",
    tone: "border-red-500/25 bg-red-500/10 text-red-400",
    icon: WifiOff,
    pulse: false,
  },
  unauthorized: {
    label: "Telemetry stream unauthorized",
    detail: "The session is no longer valid for the live stream. Sign in again.",
    tone: "border-red-500/25 bg-red-500/10 text-red-400",
    icon: WifiOff,
    pulse: false,
  },
  idle: {
    label: "Telemetry stream idle",
    detail: "The live channel has not been opened yet.",
    tone: "border-slate-600/30 bg-slate-700/10 text-slate-300",
    icon: Radio,
    pulse: false,
  },
};

export default function LiveEventBanner({
  totalEvents,
  connectionStatus = "connected",
  liveCount = 0,
}: Props) {
  const presentation = PRESENTATION[connectionStatus] ?? PRESENTATION.idle;
  const Icon = presentation.icon;

  return (
    <div
      className={`flex items-center justify-between rounded-xl border px-5 py-4 ${presentation.tone}`}
    >
      <div className="flex items-center gap-3">
        <Icon className={presentation.pulse ? "animate-pulse" : ""} size={20} />

        <div>
          <h3 className="font-semibold text-white">{presentation.label}</h3>

          <p className="text-sm text-slate-300">
            {presentation.detail}
            {liveCount > 0 && connectionStatus === "connected" && (
              <span className="ml-1 text-slate-400">
                {liveCount} received in this session.
              </span>
            )}
          </p>
        </div>
      </div>

      <div className="text-right">
        <p className="text-xs text-slate-400">Total Events</p>

        <p className="text-2xl font-bold text-cyan-400">{totalEvents}</p>
      </div>
    </div>
  );
}
