import AnimatedStatCard from "../../../components/ui/AnimatedStatCard";
import type { Incident } from "../types";

import {
  AlertTriangle,
  ShieldAlert,
  CheckCircle2,
  Clock3,
} from "lucide-react";

interface IncidentStatsProps {
  incidents: Incident[];
}

export default function IncidentStats({
  incidents,
}: IncidentStatsProps) {
  const open = incidents.filter(
    (i) => i.status === "Open"
  ).length;

  const investigating = incidents.filter(
    (i) => i.status === "Investigating"
  ).length;

  const resolved = incidents.filter(
    (i) => i.status === "Resolved"
  ).length;

  const stats = [
    {
      title: "Open",
      value: open,
      icon: AlertTriangle,
      color: "text-red-400",
      trend: `${open} Active`,
      trendPositive: false,
    },
    {
      title: "Investigating",
      value: investigating,
      icon: ShieldAlert,
      color: "text-yellow-400",
      trend: `${investigating} Active`,
      trendPositive: false,
    },
    {
      title: "Resolved",
      value: resolved,
      icon: CheckCircle2,
      color: "text-green-400",
      trend: `${resolved} Closed`,
      trendPositive: true,
    },
    {
      title: "Total Incidents",
      value: incidents.length,
      icon: Clock3,
      color: "text-cyan-400",
      trend: "Live",
      trendPositive: true,
    },
  ];

  return (
    <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
      {stats.map((item, index) => (
        <AnimatedStatCard
          key={item.title}
          {...item}
          delay={index * 0.12}
        />
      ))}
    </div>
  );
}