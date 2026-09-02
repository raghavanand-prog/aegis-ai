import { useState } from "react";

import Card from "@/components/ui/Card";
import CardHeader from "@/components/ui/CardHeader";
import CardContent from "@/components/ui/CardContent";

import {
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";

const weekly = [
  { label: "Mon", threats: 24 },
  { label: "Tue", threats: 38 },
  { label: "Wed", threats: 30 },
  { label: "Thu", threats: 45 },
  { label: "Fri", threats: 60 },
  { label: "Sat", threats: 48 },
  { label: "Sun", threats: 72 },
];

const daily = [
  { label: "00", threats: 5 },
  { label: "04", threats: 8 },
  { label: "08", threats: 18 },
  { label: "12", threats: 24 },
  { label: "16", threats: 30 },
  { label: "20", threats: 22 },
  { label: "24", threats: 15 },
];

const monthly = [
  { label: "Week 1", threats: 180 },
  { label: "Week 2", threats: 220 },
  { label: "Week 3", threats: 260 },
  { label: "Week 4", threats: 305 },
];

type Range = "24H" | "7D" | "30D";

export default function ThreatTrendChart() {
  const [range, setRange] = useState<Range>("7D");

  const data =
    range === "24H"
      ? daily
      : range === "30D"
      ? monthly
      : weekly;

  const totalThreats = data.reduce(
    (sum, item) => sum + item.threats,
    0
  );

  return (
    <Card>
      <CardHeader
        title="Threat Trend"
        subtitle={`${range} • ${totalThreats} threats detected`}
      />

      <CardContent>
        <div className="mb-5 flex gap-2">
          {(["24H", "7D", "30D"] as Range[]).map((item) => (
            <button
              key={item}
              onClick={() => setRange(item)}
              className={`rounded-lg px-3 py-1.5 text-sm font-medium transition ${
                range === item
                  ? "bg-cyan-600 text-white"
                  : "bg-slate-800 text-slate-300 hover:bg-slate-700"
              }`}
            >
              {item}
            </button>
          ))}
        </div>

        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data}>
              <CartesianGrid
                stroke="#1e293b"
                strokeDasharray="4 4"
              />

              <XAxis
                dataKey="label"
                stroke="#94a3b8"
              />

              <YAxis stroke="#94a3b8" />

              <Tooltip
                contentStyle={{
                  backgroundColor: "#0f172a",
                  border: "1px solid #334155",
                  borderRadius: "10px",
                  color: "#fff",
                }}
                labelStyle={{
                  color: "#fff",
                }}
              />

              <Line
                type="monotone"
                dataKey="threats"
                stroke="#06b6d4"
                strokeWidth={3}
                dot={{ r: 4 }}
                activeDot={{ r: 7 }}
                animationDuration={800}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}