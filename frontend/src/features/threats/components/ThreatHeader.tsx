import { RefreshCw, Search } from "lucide-react";

export default function ThreatHeader() {
  return (
    <div className="mb-8 flex items-center justify-between">
      <div>
        <h1 className="text-3xl font-bold text-white">
          Threat Intelligence
        </h1>

        <p className="mt-2 text-slate-400">
          Monitor emerging threats, IOCs, malware activity, and CVEs.
        </p>
      </div>

      <div className="flex items-center gap-4">
        <div className="relative">
          <Search
            size={18}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
          />

          <input
            type="text"
            placeholder="Search IOC..."
            className="rounded-lg border border-slate-700 bg-slate-900 py-2 pl-10 pr-4 text-white outline-none focus:border-blue-500"
          />
        </div>

        <button className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 font-medium transition hover:bg-blue-700">
          <RefreshCw size={18} />
          Refresh
        </button>
      </div>
    </div>
  );
}