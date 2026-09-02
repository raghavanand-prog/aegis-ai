import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import Card from "@/components/ui/Card";
import CardHeader from "@/components/ui/CardHeader";
import CardContent from "@/components/ui/CardContent";
import { EmptyState, ErrorState, SkeletonBlock } from "@/components/ui";

import { useAnalyticsSummary } from "../hooks/useAnalytics";
import { ACCENT_SOFT, AXIS, GRID, tooltipStyle } from "./chartTheme";

export default function AttackSourcesChart() {
  const { data, isLoading, isError, error, refetch } = useAnalyticsSummary();

  const sources =
    data?.eventsBySource.map((bucket) => ({
      source: bucket.key,
      count: bucket.count,
    })) ?? [];

  return (
    <Card>
      <CardHeader
        title="Telemetry Sources"
        subtitle="Where the events in this environment are coming from"
      />

      <CardContent>
        {isLoading ? (
          <SkeletonBlock className="h-64" />
        ) : isError ? (
          <ErrorState error={error} onRetry={() => void refetch()} />
        ) : sources.length === 0 ? (
          <EmptyState
            title="No sources reporting"
            description="Start the backend telemetry collector to populate this chart."
          />
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={sources}>
              <CartesianGrid strokeDasharray="3 3" stroke={GRID} vertical={false} />
              <XAxis
                dataKey="source"
                stroke={AXIS}
                fontSize={11}
                interval={0}
                angle={-15}
                textAnchor="end"
                height={60}
              />
              <YAxis stroke={AXIS} fontSize={12} allowDecimals={false} />
              <Tooltip {...tooltipStyle} />
              <Bar dataKey="count" name="Events" fill={ACCENT_SOFT} radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
