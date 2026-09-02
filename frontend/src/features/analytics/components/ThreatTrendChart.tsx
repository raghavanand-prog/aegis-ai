import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import Card from "@/components/ui/Card";
import CardHeader from "@/components/ui/CardHeader";
import CardContent from "@/components/ui/CardContent";
import { ErrorState, SkeletonBlock } from "@/components/ui";

import { useAnalyticsSummary } from "../hooks/useAnalytics";
import { formatHourBucket } from "@/lib/time";
import { ACCENT, AXIS, GRID, SEVERITY_COLORS, tooltipStyle } from "./chartTheme";

export default function ThreatTrendChart() {
  const { data, isLoading, isError, error, refetch } = useAnalyticsSummary();

  const series =
    data?.eventsOverTime.map((bucket) => ({
      label: formatHourBucket(bucket.bucket),
      events: bucket.count,
      critical: bucket.critical,
      high: bucket.high,
    })) ?? [];

  const total = series.reduce((sum, point) => sum + point.events, 0);

  return (
    <Card>
      <CardHeader
        title="Event Volume"
        subtitle={
          data
            ? `${total.toLocaleString()} events in the last ${data.windowHours}h`
            : "Loading time series..."
        }
      />

      <CardContent>
        {isLoading ? (
          <SkeletonBlock className="h-64" />
        ) : isError ? (
          <ErrorState error={error} onRetry={() => void refetch()} />
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={series}>
              <defs>
                <linearGradient id="eventsGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={ACCENT} stopOpacity={0.45} />
                  <stop offset="100%" stopColor={ACCENT} stopOpacity={0} />
                </linearGradient>
              </defs>

              <CartesianGrid strokeDasharray="3 3" stroke={GRID} />
              <XAxis dataKey="label" stroke={AXIS} fontSize={12} />
              <YAxis stroke={AXIS} fontSize={12} allowDecimals={false} />
              <Tooltip {...tooltipStyle} />
              <Legend wrapperStyle={{ fontSize: "0.75rem", color: AXIS }} />

              <Area
                type="monotone"
                dataKey="events"
                name="All events"
                stroke={ACCENT}
                fill="url(#eventsGradient)"
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="critical"
                name="Critical"
                stroke={SEVERITY_COLORS.Critical}
                fill={SEVERITY_COLORS.Critical}
                fillOpacity={0.15}
                strokeWidth={2}
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
