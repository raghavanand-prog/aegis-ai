import { aiInsights } from "@/data/dashboard";
import { Brain } from "lucide-react";

export default function AIInsights() {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg">
      <div className="mb-6 flex items-center gap-3">
        <div className="rounded-xl bg-cyan-500/10 p-3">
          <Brain className="h-6 w-6 text-cyan-400" />
        </div>

        <div>
          <h2 className="text-lg font-semibold text-white">
            AI Security Insights
          </h2>

          <p className="text-sm text-slate-400">
            AI-generated threat analysis
          </p>
        </div>
      </div>

      <div className="space-y-5">
        {aiInsights.map((insight, index) => {
          const Icon = insight.icon;

          return (
            <div
              key={index}
              className="rounded-xl border border-slate-800 bg-slate-950/40 p-4"
            >
              <div className="flex items-start gap-4">
                <div className="rounded-lg bg-slate-800 p-2">
                  <Icon className="h-5 w-5 text-cyan-400" />
                </div>

                <div className="flex-1">
                  <h3 className="font-semibold text-white">
                    {insight.title}
                  </h3>

                  <p className="mt-2 text-sm leading-relaxed text-slate-400">
                    {insight.description}
                  </p>

                  <div className="mt-4">
                    <div className="mb-1 flex justify-between text-xs text-slate-400">
                      <span>Confidence</span>
                      <span>{insight.confidence}</span>
                    </div>

                    <div className="h-2 rounded-full bg-slate-800">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500"
                        style={{
                          width: insight.confidence,
                        }}
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}