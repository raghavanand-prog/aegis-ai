import { useMemo, useState } from "react";
import { Search } from "lucide-react";
import { threats } from "../data/threats";

export default function IOCTable() {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("All");

  function severityColor(severity: string) {
    switch (severity) {
      case "Critical":
        return "bg-red-500/10 text-red-400 border border-red-500/20";
      case "High":
        return "bg-orange-500/10 text-orange-400 border border-orange-500/20";
      case "Medium":
        return "bg-yellow-500/10 text-yellow-300 border border-yellow-500/20";
      case "Low":
        return "bg-blue-500/10 text-blue-400 border border-blue-500/20";
      default:
        return "bg-slate-700 text-slate-300 border border-slate-600";
    }
  }

  const filteredThreats = useMemo(() => {
    return threats.filter((ioc) => {
      const matchesSearch =
        ioc.indicator.toLowerCase().includes(search.toLowerCase()) ||
        ioc.source.toLowerCase().includes(search.toLowerCase());

      const matchesSeverity =
        severity === "All" || ioc.severity === severity;

      return matchesSearch && matchesSeverity;
    });
  }, [search, severity]);

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
      <div className="mb-6 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <h2 className="text-xl font-semibold text-white">
          Indicators of Compromise
        </h2>

        <div className="flex gap-3">
          <div className="relative">
            <Search className="absolute left-3 top-3 h-4 w-4 text-slate-500" />

            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search IOC..."
              className="rounded-lg border border-slate-700 bg-slate-800 py-2 pl-10 pr-4 text-sm text-white outline-none focus:border-cyan-500"
            />
          </div>

          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 text-sm text-white outline-none focus:border-cyan-500"
          >
            <option>All</option>
            <option>Critical</option>
            <option>High</option>
            <option>Medium</option>
            <option>Low</option>
          </select>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="border-b border-slate-800 text-left text-sm text-slate-400">
            <tr>
              <th className="pb-4">Indicator</th>
              <th>Type</th>
              <th>Severity</th>
              <th>Source</th>
              <th>Status</th>
              <th>Last Seen</th>
            </tr>
          </thead>

          <tbody>
            {filteredThreats.map((ioc) => (
              <tr
                key={ioc.id}
                className="border-b border-slate-800 transition hover:bg-slate-800/40"
              >
                <td className="py-4 font-medium text-white">
                  {ioc.indicator}
                </td>

                <td className="text-slate-300">{ioc.type}</td>

                <td>
                  <span
                    className={`rounded-full px-3 py-1 text-xs font-medium ${severityColor(
                      ioc.severity
                    )}`}
                  >
                    {ioc.severity}
                  </span>
                </td>

                <td className="text-slate-300">{ioc.source}</td>

                <td className="text-emerald-400">{ioc.status}</td>

                <td className="text-slate-400">{ioc.lastSeen}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}