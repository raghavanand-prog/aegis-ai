import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

import Card from "@/components/ui/Card";
import CardHeader from "@/components/ui/CardHeader";
import CardContent from "@/components/ui/CardContent";
import { EmptyState, ErrorState, SkeletonBlock } from "@/components/ui";

import { useAnalyticsSummary } from "../hooks/useAnalytics";
import { SEVERITY_COLORS, tooltipStyle } from "./chartTheme";

export default function SeverityDonut() {
  const { data, isLoading, isError, error, refetch } = useAnalyticsSummary();

  const slices =
    data?.eventsBySeverity
      .filter((bucket) => bucket.count > 0)
      .map((bucket) => ({ name: bucket.key, value: bucket.count })) ?? [];

  const total = slices.reduce((sum, slice) => sum + slice.value, 0);

  return (
    <Card>
      <CardHeader
        title="Events by Severity"
        subtitle={`${total.toLocaleString()} classified events`}
      />

      <CardContent>
        {isLoading ? (
          <SkeletonBlock className="h-64" />
        ) : isError ? (
          <ErrorState error={error} onRetry={() => void refetch()} />
        ) : slices.length === 0 ? (
          <EmptyState title="No events yet" description="Severity breaks down here once telemetry arrives." />
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie
                data={slices}
                dataKey="value"
                nameKey="name"
                innerRadius={60}
                outerRadius={95}
                paddingAngle={3}
                stroke="none"
              >
                {slices.map((slice) => (
                  <Cell
                    key={slice.name}
                    fill={SEVERITY_COLORS[slice.name] ?? "#64748b"}
                  />
                ))}
              </Pie>

              <Tooltip {...tooltipStyle} />
              <Legend wrapperStyle={{ fontSize: "0.75rem" }} />
            </PieChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
