import { Search } from "lucide-react";

export default function IncidentFilters() {
  return (
    <div className="flex flex-col gap-4 rounded-xl border border-slate-800 bg-slate-900 p-5 lg:flex-row">
      <div className="relative flex-1">
        <Search className="absolute left-3 top-3 h-5 w-5 text-slate-500" />

        <input
          type="text"
          placeholder="Search incidents..."
          className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-10 pr-4 text-white outline-none focus:border-cyan-500"
        />
      </div>

      <select className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-white">
        <option>All Severities</option>
        <option>Critical</option>
        <option>High</option>
        <option>Medium</option>
        <option>Low</option>
      </select>

      <select className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-white">
        <option>All Status</option>
        <option>Open</option>
        <option>Investigating</option>
        <option>Contained</option>
        <option>Resolved</option>
      </select>
    </div>
  );
}