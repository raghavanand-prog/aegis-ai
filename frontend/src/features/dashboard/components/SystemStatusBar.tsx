import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, CloudOff, Radio, WifiOff } from "lucide-react";

import { fetchSystemHealth } from "@/services/api/health";
import { useRealtimeStatus } from "@/services/realtime/useRealtime";
import { useAuth } from "@/features/auth/hooks/useAuth";

/**
 * One line that tells the analyst whether what they are looking at is current.
 *
 * A SOC console that silently shows stale data is worse than one that says it
 * is offline, so this appears whenever the browser, the API, the telemetry
 * collector or the live stream is not fully healthy - and stays out of the way
 * when everything is fine.
 */
export default function SystemStatusBar() {
  const { isAuthenticated } = useAuth();
  const streamStatus = useRealtimeStatus(isAuthenticated);
  const [browserOnline, setBrowserOnline] = useState(
    typeof navigator === "undefined" ? true : navigator.onLine,
  );

  useEffect(() => {
    const online = () => setBrowserOnline(true);
    const offline = () => setBrowserOnline(false);
    window.addEventListener("online", online);
    window.addEventListener("offline", offline);
    return () => {
      window.removeEventListener("online", online);
      window.removeEventListener("offline", offline);
    };
  }, []);

  const health = useQuery({
    queryKey: ["health", "system"],
    queryFn: fetchSystemHealth,
    enabled: isAuthenticated,
    refetchInterval: 30_000,
    retry: 1,
  });

  if (!isAuthenticated) return null;

  if (!browserOnline) {
    return (
      <Banner
        tone="border-red-500/30 bg-red-500/10 text-red-200"
        icon={<CloudOff size={16} className="text-red-400" />}
        title="You are offline"
        detail="The browser has no network connection. Data on screen is from your last successful load."
      />
    );
  }

  if (health.isError) {
    return (
      <Banner
        tone="border-red-500/30 bg-red-500/10 text-red-200"
        icon={<WifiOff size={16} className="text-red-400" />}
        title="Backend unreachable"
        detail="AEGISX cannot reach the API. Events and incidents shown may be out of date."
      />
    );
  }

  const system = health.data;
  const streamDown = streamStatus === "disconnected" || streamStatus === "unauthorized";
  const streamRetrying = streamStatus === "reconnecting";
  const degraded = system?.status === "degraded" || system?.status === "unavailable";

  if (!degraded && !streamDown && !streamRetrying) return null;

  const reasons: string[] = [];
  if (system?.telemetry?.status !== "healthy") {
    reasons.push(
      system?.telemetry?.reason
        ? `telemetry ${system.telemetry.status} (${system.telemetry.reason})`
        : `telemetry ${system?.telemetry?.status ?? "unknown"}`,
    );
  }
  if (system?.database?.status !== "healthy") {
    reasons.push(`database ${system?.database?.status ?? "unknown"}`);
  }
  if (streamDown) reasons.push("live stream disconnected");
  if (streamRetrying) reasons.push("live stream reconnecting");

  return (
    <Banner
      tone="border-amber-500/30 bg-amber-500/10 text-amber-100"
      icon={
        streamRetrying ? (
          <Radio size={16} className="animate-pulse text-amber-400" />
        ) : (
          <AlertTriangle size={16} className="text-amber-400" />
        )
      }
      title="System degraded"
      detail={reasons.join(" · ")}
    />
  );
}

function Banner({
  tone,
  icon,
  title,
  detail,
}: {
  tone: string;
  icon: React.ReactNode;
  title: string;
  detail: string;
}) {
  return (
    <div
      role="status"
      className={`flex items-center gap-3 border-b px-6 py-2 text-sm ${tone}`}
    >
      {icon}
      <span className="font-semibold">{title}</span>
      <span className="text-slate-300">{detail}</span>
    </div>
  );
}
