import DashboardHeader from "../../features/dashboard/components/DashboardHeader";
import LiveAlertBanner from "../../features/dashboard/components/LiveAlertBanner";
import DashboardStats from "../../features/dashboard/components/DashboardStats";
import ThreatTrendChart from "../../features/dashboard/components/ThreatTrendChart";
import ThreatOverview from "../../features/dashboard/components/ThreatOverview";
import ThreatTable from "../../features/dashboard/components/ThreatTable";
import AIInsights from "../../features/dashboard/components/AIInsights";
import RecentActivity from "../../features/dashboard/components/RecentActivity";
import AttackSources from "../../features/dashboard/components/AttackSources";
import MitreCoverage from "../../features/dashboard/components/MitreCoverage";


export default function DashboardPage() {
  return (
    <div className="space-y-8">
      <DashboardHeader />

      <LiveAlertBanner />

      <DashboardStats />

      <div className="grid gap-8 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <ThreatTrendChart />
        </div>

        <ThreatOverview />
      </div>

      <div className="grid gap-8 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <ThreatTable />
        </div>

        <AIInsights />
      </div>

      <div className="grid gap-8 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <RecentActivity />
        </div>

        <AttackSources />
      </div>

      <MitreCoverage />
    </div>
  );
}