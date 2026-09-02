import Card from "@/components/ui/Card";
import CardHeader from "@/components/ui/CardHeader";
import CardContent from "@/components/ui/CardContent";

import ActivityItem from "./ActivityItem";
import { recentActivities } from "@/data/dashboard";

export default function RecentActivity() {
  return (
    <Card>
      <div className="flex items-center justify-between border-b border-slate-800 px-6 py-4">
        <CardHeader
          title="Recent Activity"
          subtitle="Latest security events across your infrastructure"
        />

        <div className="flex items-center gap-2 rounded-full bg-emerald-500/10 px-3 py-1">
          <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />

          <span className="text-xs font-semibold uppercase tracking-wider text-emerald-400">
            Live
          </span>
        </div>
      </div>

      <CardContent>
        <div className="max-h-[430px] space-y-4 overflow-y-auto pr-2">
          {recentActivities.map((activity) => (
            <ActivityItem
              key={activity.id}
              activity={activity}
            />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}