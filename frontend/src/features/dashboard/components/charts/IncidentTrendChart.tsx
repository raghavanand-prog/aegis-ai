import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";

const data = [
  { day: "Mon", incidents: 12 },
  { day: "Tue", incidents: 19 },
  { day: "Wed", incidents: 15 },
  { day: "Thu", incidents: 24 },
  { day: "Fri", incidents: 18 },
  { day: "Sat", incidents: 10 },
  { day: "Sun", incidents: 14 },
];

export default function IncidentTrendChart() {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      <h3 className="mb-4 text-lg font-semibold text-white">
        Incident Trend
      </h3>

      <ResponsiveContainer width="100%" height={250}>
        <LineChart data={data}>
          <CartesianGrid stroke="#334155" />

          <XAxis dataKey="day" stroke="#94A3B8" />

          <YAxis stroke="#94A3B8" />

          <Tooltip />

          <Line
            type="monotone"
            dataKey="incidents"
            stroke="#06b6d4"
            strokeWidth={3}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}