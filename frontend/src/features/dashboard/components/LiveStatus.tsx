import { Wifi } from "lucide-react";

export default function LiveStatus() {
  return (
    <div className="flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-4 py-2">

      <span className="relative flex h-3 w-3">

        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>

        <span className="relative inline-flex h-3 w-3 rounded-full bg-emerald-400"></span>

      </span>

      <Wifi size={16} className="text-emerald-400" />

      <span className="text-sm font-medium text-emerald-300">
        Live Telemetry
      </span>

    </div>
  );
}