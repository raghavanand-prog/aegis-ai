import { Activity, Wifi } from "lucide-react";

export default function EventHeader() {
  return (
    <div className="flex items-center justify-between">
      <div>
        <h1 className="flex items-center gap-3 text-3xl font-bold text-white">
          <Activity className="text-cyan-400" />
          Live SIEM Events
        </h1>

        <p className="mt-2 text-slate-400">
          Monitor security events from connected data sources in real time.
        </p>
      </div>

      <div className="flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-4 py-2">
        <Wifi className="text-emerald-400" size={16} />
        <span className="text-sm font-medium text-emerald-400">
          Live
        </span>
      </div>
    </div>
  );
}