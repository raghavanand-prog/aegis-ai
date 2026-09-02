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
import { AXIS, GRID, MITRE, tooltipStyle } from "./chartTheme";

export default function MitreCoverageChart() {
  const { data, isLoading, isError, error, refetch } = useAnalyticsSummary();

  const techniques =
    data?.mitreCoverage.map((bucket) => ({
      technique: bucket.key,
      count: bucket.count,
    })) ?? [];

  return (
    <Card>
      <CardHeader
        title="MITRE ATT&CK Coverage"
        subtitle={
          techniques.length
            ? `${techniques.length} technique(s) observed in this window`
            : "Techniques mapped by the detection engine"
        }
      />

      <CardContent>
        {isLoading ? (
          <SkeletonBlock className="h-64" />
        ) : isError ? (
          <ErrorState error={error} onRetry={() => void refetch()} />
        ) : techniques.length === 0 ? (
          <EmptyState
            title="No techniques mapped yet"
            description="Techniques appear once a detection rule matches incoming telemetry."
          />
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={techniques} layout="vertical" margin={{ left: 24 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={GRID} horizontal={false} />
              <XAxis type="number" stroke={AXIS} fontSize={12} allowDecimals={false} />
              <YAxis
                type="category"
                dataKey="technique"
                stroke={AXIS}
                fontSize={12}
                width={80}
              />
              <Tooltip {...tooltipStyle} />
              <Bar dataKey="count" name="Detections" fill={MITRE} radius={[0, 6, 6, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
