import ThreatHeader from "../../features/threats/components/ThreatHeader";
import ThreatStats from "../../features/threats/components/ThreatStats";
import ThreatSummary from "../../features/threats/components/ThreatSummary";
import MalwareFamilies from "../../features/threats/components/MalwareFamilies";
import IOCTable from "../../features/threats/components/IOCTable";
import ThreatTrendChart from "../../features/threats/components/ThreatTrendChart";
import SeverityChart from "../../features/threats/components/SeverityChart";
import MitreCard from "../../features/threats/components/MitreCard";
import LiveThreatFeed from "../../features/threats/components/LiveThreatFeed";

export default function ThreatsPage() {
  return (
    <div className="space-y-8">
      <ThreatHeader />

      <ThreatStats />

      <div className="grid gap-8 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <ThreatSummary />
        </div>

        <MalwareFamilies />
      </div>

      <IOCTable />
    <div className="grid gap-8 xl:grid-cols-3">
  <div className="xl:col-span-2">
    <ThreatTrendChart />
  </div>

  <SeverityChart />
</div>

<MitreCard />

<LiveThreatFeed />
    </div>
    
  );
}