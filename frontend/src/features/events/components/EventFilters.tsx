import { Search } from "lucide-react";

interface EventFiltersProps {
  search: string;
  setSearch: (value: string) => void;

  severity: string;
  setSeverity: (value: string) => void;
}

export default function EventFilters({
  search,
  setSearch,
  severity,
  setSeverity,
}: EventFiltersProps) {
  return (
    <div className="flex flex-col gap-4 rounded-xl border border-slate-800 bg-slate-900 p-5 lg:flex-row lg:items-center lg:justify-between">

      {/* Search */}
      <div className="relative w-full lg:max-w-md">
        <Search
          size={18}
          className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
        />

        <input
          type="text"
          placeholder="Search events..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-10 pr-4 text-white outline-none transition focus:border-cyan-500"
        />
      </div>

      {/* Severity */}
      <select
        value={severity}
        onChange={(e) => setSeverity(e.target.value)}
        className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-white outline-none focus:border-cyan-500"
      >
        <option value="All">All Severities</option>
        <option value="Critical">Critical</option>
        <option value="High">High</option>
        <option value="Medium">Medium</option>
        <option value="Low">Low</option>
      </select>
    </div>
  );
}