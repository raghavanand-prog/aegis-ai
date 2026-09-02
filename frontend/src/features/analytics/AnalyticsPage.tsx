import AnalyticsHeader from "./components/AnalyticsHeader";
import ExecutiveKPIs from "./components/ExecutiveKPIs";
import ThreatTrendChart from "./components/ThreatTrendChart";
import SeverityDonut from "./components/SeverityDonut";
import MitreCoverageChart from "./components/MitreCoverageChart";
import AttackSourcesChart from "./components/AttackSourcesChart";
import AnalystPerformance from "./components/AnalystPerformance";
import AIInsightsPanel from "./components/AIInsightsPanel";
import ExecutiveSummary from "./components/ExecutiveSummary";
import DetectionQualityPanel from "./components/DetectionQualityPanel";
import MLAnalyticsPanel from "./components/MLAnalyticsPanel";

import ErrorBoundary from "@/components/ErrorBoundary";

/** Each panel gets its own boundary: one failing chart must not blank the page. */
function Panel({ label, children }: { label: string; children: React.ReactNode }) {
  return <ErrorBoundary label={label}>{children}</ErrorBoundary>;
}

export default function AnalyticsPage() {
  return (
    <div className="space-y-8">
      <Panel label="Analytics header">
        <AnalyticsHeader />
      </Panel>

      <Panel label="Executive KPIs">
        <ExecutiveKPIs />
      </Panel>

      <div className="grid gap-6 xl:grid-cols-2">
        <Panel label="Event volume">
          <ThreatTrendChart />
        </Panel>
        <Panel label="Severity breakdown">
          <SeverityDonut />
        </Panel>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <Panel label="MITRE coverage">
          <MitreCoverageChart />
        </Panel>
        <Panel label="Telemetry sources">
          <AttackSourcesChart />
        </Panel>
      </div>

      {/* Measured quality of the deterministic detection rules. */}
      <Panel label="Detection engine evaluation">
        <DetectionQualityPanel />
      </Panel>

      {/* V3: the second detector, counted from stored inference rows. */}
      <Panel label="ML detection">
        <MLAnalyticsPanel />
      </Panel>

      <div className="grid gap-6 xl:grid-cols-2">
        <Panel label="Analyst workload">
          <AnalystPerformance />
        </Panel>
        <Panel label="Derived insights">
          <AIInsightsPanel />
        </Panel>
      </div>

      <Panel label="Executive summary">
        <ExecutiveSummary />
      </Panel>
    </div>
  );
}
