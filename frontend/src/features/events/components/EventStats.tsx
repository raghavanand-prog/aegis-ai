import type { Event } from "../types";
import { Activity, AlertTriangle, ShieldAlert, Search } from "lucide-react";

interface Props {
  events: Event[];
}

export default function EventStats({ events }: Props) {
  const total = events.length;

  const critical = events.filter(
    (e) => e.severity === "Critical"
  ).length;

  const high = events.filter(
    (e) => e.severity === "High"
  ).length;

  const investigating = events.filter(
    (e) => e.status === "Investigating"
  ).length;

  const stats = [
    {
      title: "Total Events",
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
      title: "Investigating",
      value: investigating,
      icon: Search,
      color: "text-yellow-400",
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
              <p className="text-sm text-slate-400">{stat.title}</p>
              <h2 className="mt-2 text-3xl font-bold text-white">
                {stat.value}
              </h2>
            </div>

            <stat.icon className={stat.color} size={28} />
          </div>
        </div>
      ))}
    </div>
  );
}