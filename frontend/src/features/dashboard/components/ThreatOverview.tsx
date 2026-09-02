import Card from "@/components/ui/Card";
import CardHeader from "@/components/ui/CardHeader";
import CardContent from "@/components/ui/CardContent";

import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from "recharts";

const threatData = [
  {
    name: "Malware",
    value: 42,
    count: 524,
    trend: "+8%",
    color: "#3B82F6",
  },
  {
    name: "Phishing",
    value: 28,
    count: 349,
    trend: "-2%",
    color: "#EF4444",
  },
  {
    name: "Ransomware",
    value: 18,
    count: 225,
    trend: "+5%",
    color: "#F59E0B",
  },
  {
    name: "Insider",
    value: 7,
    count: 87,
    trend: "0%",
    color: "#22C55E",
  },
  {
    name: "Zero-Day",
    value: 5,
    count: 63,
    trend: "+1%",
    color: "#8B5CF6",
  },
];

const totalThreats = threatData.reduce(
  (sum, item) => sum + item.count,
  0
);

export default function ThreatOverview() {
  return (
    <Card>
      <CardHeader
        title="Threat Overview"
        subtitle="Threat distribution over the last 7 days"
      />

      <CardContent>
        {/* Donut Chart */}
        <div className="relative h-56">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={threatData}
                dataKey="value"
                innerRadius={58}
                outerRadius={82}
                paddingAngle={4}
                cornerRadius={8}
              >
                {threatData.map((item) => (
                  <Cell
                    key={item.name}
                    fill={item.color}
                  />
                ))}
              </Pie>

              <Tooltip
                contentStyle={{
                  backgroundColor: "#0f172a",
                  border: "1px solid #334155",
                  borderRadius: "12px",
                  color: "#fff",
                }}
              />
            </PieChart>
          </ResponsiveContainer>

          {/* Center Label */}
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
            <p className="text-3xl font-bold text-white">
              {totalThreats.toLocaleString()}
            </p>

            <p className="text-xs uppercase tracking-wider text-slate-400">
              Total Threats
            </p>
          </div>
        </div>

        {/* Compact Legend */}
        <div className="mt-3 space-y-2">
          {threatData.map((item) => (
            <div
              key={item.name}
              className="flex items-center justify-between rounded-lg px-3 py-2 transition-all duration-300 hover:bg-slate-800/60"
            >
              <div className="flex items-center gap-3">
                <span
                  className="h-2.5 w-2.5 rounded-full"
                  style={{
                    backgroundColor: item.color,
                  }}
                />

                <span className="font-medium text-white">
                  {item.name}
                </span>
              </div>

              <div className="flex items-center gap-5">
                <span className="w-12 text-right text-sm text-slate-400">
                  {item.count}
                </span>

                <span className="w-10 text-right font-semibold text-white">
                  {item.value}%
                </span>

                <span
                  className={`w-10 text-right text-sm font-semibold ${
                    item.trend.startsWith("+")
                      ? "text-emerald-400"
                      : item.trend.startsWith("-")
                      ? "text-red-400"
                      : "text-slate-500"
                  }`}
                >
                  {item.trend}
                </span>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}