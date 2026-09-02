import { useState } from "react";
import { RefreshCw } from "lucide-react";

import Card from "@/components/ui/Card";
import CardHeader from "@/components/ui/CardHeader";
import CardContent from "@/components/ui/CardContent";
import Badge from "@/components/ui/Badge";

import ThreatDetailsDrawer from "./ThreatDetailsDrawer";
import { threatQueue } from "@/data/dashboard";

type Threat = {
  id: string;
  threat: string;
  severity: "critical" | "high" | "medium" | "low";
  source: string;
  status:
    | "active"
    | "investigating"
    | "blocked"
    | "contained"
    | "resolved";
  time: string;
};

export default function ThreatTable() {
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");

  const filteredThreats = threatQueue.filter((threat) => {
    const matchesSearch = threat.threat
      .toLowerCase()
      .includes(search.toLowerCase());

    const matchesSeverity =
      severityFilter === "all" ||
      threat.severity === severityFilter;

    const matchesStatus =
      statusFilter === "all" ||
      threat.status === statusFilter;

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  return (
    <>
      <Card>
        <CardHeader
          title="Threat Queue"
          subtitle="Live threat events detected across the environment"
        />

        {/* Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-4 px-6 pt-2">
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500 animate-pulse"></span>

            <span className="text-xs font-semibold uppercase tracking-widest text-emerald-400">
              LIVE
            </span>
          </div>

          <button className="flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 transition hover:bg-slate-800">
            <RefreshCw size={16} />
            Refresh
          </button>
        </div>

        {/* Search + Filters */}
        <div className="flex flex-wrap gap-4 px-6 pt-4">
          <input
            type="text"
            placeholder="Search threats..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="flex-1 rounded-xl border border-slate-700 bg-slate-800 px-4 py-2 text-white placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none"
          />

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded-xl border border-slate-700 bg-slate-800 px-4 py-2 text-white"
          >
            <option value="all">All Severity</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-xl border border-slate-700 bg-slate-800 px-4 py-2 text-white"
          >
            <option value="all">All Status</option>
            <option value="active">Active</option>
            <option value="investigating">Investigating</option>
            <option value="blocked">Blocked</option>
            <option value="contained">Contained</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>

        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="py-4 text-left text-sm font-semibold text-slate-400">
                    Threat
                  </th>

                  <th className="py-4 text-left text-sm font-semibold text-slate-400">
                    Severity
                  </th>

                  <th className="py-4 text-left text-sm font-semibold text-slate-400">
                    Source
                  </th>

                  <th className="py-4 text-left text-sm font-semibold text-slate-400">
                    Status
                  </th>

                  <th className="py-4 text-left text-sm font-semibold text-slate-400">
                    Detected
                  </th>

                  <th className="py-4 text-left text-sm font-semibold text-slate-400">
                    Action
                  </th>
                </tr>
              </thead>

              <tbody>
                {filteredThreats.map((threat) => (
                  <tr
                    key={threat.id}
                    className="border-b border-border/40 transition hover:bg-slate-800/40"
                  >
                    <td className="py-5 font-medium text-white">
                      {threat.threat}
                    </td>

                    <td className="py-5">
                      <Badge variant={threat.severity}>
                        {threat.severity.toUpperCase()}
                      </Badge>
                    </td>

                    <td className="py-5 text-slate-300">
                      {threat.source}
                    </td>

                    <td className="py-5">
                      <Badge variant={threat.status}>
                        {threat.status.toUpperCase()}
                      </Badge>
                    </td>

                    <td className="py-5 text-slate-400">
                      {threat.time}
                    </td>

                    <td className="py-5">
                      <button
                        onClick={() => setSelectedThreat(threat)}
                        className="rounded-lg bg-cyan-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-cyan-500"
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))}

                {filteredThreats.length === 0 && (
                  <tr>
                    <td
                      colSpan={6}
                      className="py-8 text-center text-slate-500"
                    >
                      No threats found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      <ThreatDetailsDrawer
        threat={selectedThreat}
        onClose={() => setSelectedThreat(null)}
      />
    </>
  );
}