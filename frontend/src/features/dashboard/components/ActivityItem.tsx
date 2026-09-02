import type { LucideIcon } from "lucide-react";

interface ActivityItemProps {
  activity: {
    id: number;
    title: string;
    description: string;
    severity: string;
    time: string;
    icon: LucideIcon;
  };
}

export default function ActivityItem({
  activity,
}: ActivityItemProps) {
  const Icon = activity.icon;

  const severityColors = {
    Critical: "bg-red-500/15 text-red-400 border-red-500/30",
    High: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    Medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    Low: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  };

  return (
    <div className="group flex items-start gap-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4 transition-all duration-300 hover:border-blue-500/40 hover:bg-slate-800/60 hover:shadow-lg hover:shadow-blue-500/10">
      <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-blue-500/10 text-blue-400 transition-transform duration-300 group-hover:scale-110">
        <Icon size={20} />
      </div>

      <div className="flex-1">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-white">
            {activity.title}
          </h3>

          <span
            className={`rounded-full border px-3 py-1 text-xs font-medium ${
              severityColors[
                activity.severity as keyof typeof severityColors
              ]
            }`}
          >
            {activity.severity}
          </span>
        </div>

        <p className="mt-1 text-sm text-slate-400">
          {activity.description}
        </p>

        <p className="mt-3 text-xs text-slate-500">
          {activity.time}
        </p>
      </div>
    </div>
  );
}