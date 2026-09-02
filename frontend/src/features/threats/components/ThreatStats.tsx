import {
  ShieldAlert,
  Bug,
  Globe,
  AlertTriangle,
} from "lucide-react";

const stats = [
  {
    title: "Active Threats",
    value: "128",
    icon: ShieldAlert,
    color: "text-red-500",
  },
  {
    title: "Critical Alerts",
    value: "23",
    icon: AlertTriangle,
    color: "text-orange-400",
  },
  {
    title: "Malware Families",
    value: "54",
    icon: Bug,
    color: "text-purple-400",
  },
  {
    title: "Known IOCs",
    value: "12,483",
    icon: Globe,
    color: "text-blue-400",
  },
];

export default function ThreatStats() {
  return (
    <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
      {stats.map((stat) => {
        const Icon = stat.icon;

        return (
          <div
            key={stat.title}
            className="rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-lg transition hover:border-blue-500"
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

              <Icon className={`h-10 w-10 ${stat.color}`} />
            </div>
          </div>
        );
      })}
    </div>
  );
}