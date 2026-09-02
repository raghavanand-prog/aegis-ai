import { ShieldCheck } from "lucide-react";
import { mitreCoverage } from "@/data/dashboard";

const statusStyles = {
  Protected: {
    dot: "bg-emerald-500",
    badge: "bg-emerald-500/10 text-emerald-400",
  },
  Partial: {
    dot: "bg-yellow-500",
    badge: "bg-yellow-500/10 text-yellow-400",
  },
  Missing: {
    dot: "bg-red-500",
    badge: "bg-red-500/10 text-red-400",
  },
};

export default function MitreCoverage() {
  const protectedCount = mitreCoverage.filter(
    (item) => item.status === "Protected"
  ).length;

  const coverage = Math.round(
    (protectedCount / mitreCoverage.length) * 100
  );

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg">
      <div className="mb-6 flex items-center gap-3">
        <div className="rounded-xl bg-emerald-500/10 p-3">
          <ShieldCheck className="h-6 w-6 text-emerald-400" />
        </div>

        <div>
          <h2 className="text-lg font-semibold text-white">
            MITRE ATT&CK Coverage
          </h2>

          <p className="text-sm text-slate-400">
            Detection coverage overview
          </p>
        </div>
      </div>

      <div className="space-y-4">
        {mitreCoverage.map((item) => {
          const style = statusStyles[item.status];

          return (
            <div
              key={item.tactic}
              className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-3"
            >
              <div className="flex items-center gap-3">
                <div
                  className={`h-3 w-3 rounded-full ${style.dot}`}
                />

                <span className="text-sm text-white">
                  {item.tactic}
                </span>
              </div>

              <span
                className={`rounded-full px-3 py-1 text-xs font-semibold ${style.badge}`}
              >
                {item.status}
              </span>
            </div>
          );
        })}
      </div>

      <div className="mt-8 border-t border-slate-800 pt-6">
        <div className="mb-2 flex justify-between text-sm">
          <span className="text-slate-400">
            Overall Coverage
          </span>

          <span className="font-semibold text-white">
            {coverage}%
          </span>
        </div>

        <div className="h-3 overflow-hidden rounded-full bg-slate-800">
          <div
            className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-cyan-500"
            style={{
              width: `${coverage}%`,
            }}
          />
        </div>
      </div>
    </div>
  );
}