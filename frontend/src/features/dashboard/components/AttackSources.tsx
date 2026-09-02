import Card from "@/components/ui/Card";
import CardHeader from "@/components/ui/CardHeader";
import CardContent from "@/components/ui/CardContent";

import { attackSources } from "@/data/dashboard";

export default function AttackSources() {
  return (
    <Card>
      <CardHeader
        title="Attack Sources"
        subtitle="Top origin countries"
      />

      <CardContent>

        <div className="space-y-5">

          {attackSources.map((source) => (

            <div key={source.code}>

              <div className="mb-2 flex items-center justify-between">

                <div className="flex items-center gap-3">

                  <span className="rounded-md bg-slate-800 px-2 py-1 text-xs font-bold text-slate-300">
                    {source.code}
                  </span>

                  <span className="text-sm font-medium text-white">
                    {source.country}
                  </span>

                </div>

                <span className="text-sm font-semibold text-white">
                  {source.attacks}
                </span>

              </div>

              <div className="h-2 overflow-hidden rounded-full bg-slate-800">

                <div
                  className="h-full rounded-full bg-gradient-to-r from-blue-500 to-cyan-400 transition-all duration-500"
                  style={{
                    width: `${source.percentage}%`,
                  }}
                />

              </div>

            </div>

          ))}

        </div>

        <div className="mt-8 border-t border-slate-800 pt-6">

          <p className="text-4xl font-bold text-white">
            136
          </p>

          <p className="text-sm text-slate-400">
            Blocked Today
          </p>

          <p className="mt-2 text-sm font-semibold text-emerald-400">
            ↑ 12% vs Yesterday
          </p>

        </div>

      </CardContent>
    </Card>
  );
}