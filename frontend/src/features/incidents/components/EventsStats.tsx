import type { Incident } from "../types";
import {
  Activity,
  AlertTriangle,
  ShieldAlert,
  CheckCircle,
} from "lucide-react";

interface Props {
  incidents: Incident[];
}

export default function IncidentStats({ incidents }: Props) {
  const total = incidents.length;

  const critical = incidents.filter(
    (i) => i.severity === "Critical"
  ).length;

  const high = incidents.filter(
    (i) => i.severity === "High"
  ).length;

  const resolved = incidents.filter(
    (i) => i.status === "Resolved"
  ).length;

  const stats = [
    {
      title: "Total Incidents",
      value: total,
      icon: Activity,
      color: "text-cyan-400",
    },
    {
      title: "Critical",
      value: critical,
      icon: AlertTriangle,
      color: "text-red-400",
    },
    {
      title: "High",
      value: high,
      icon: ShieldAlert,
      color: "text-orange-400",
    },
    {
      title: "Resolved",
      value: resolved,
      icon: CheckCircle,
      color: "text-green-400",
    },
  ];

  return (
    <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
      {stats.map((stat) => (
        <div
          key={stat.title}
          className="rounded-xl border border-slate-800 bg-slate-900 p-5"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">
                {stat.title}
              </p>

              <h2 className="mt-2 text-3xl font-bold text-white">
                {stat.value}
              </h2>
            </div>

            <stat.icon
              className={stat.color}
              size={28}
            />
          </div>
        </div>
      ))}
    </div>
  );
}