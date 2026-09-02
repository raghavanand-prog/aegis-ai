import {
  Brain,
  ShieldAlert,
  TrendingUp,
} from "lucide-react";

export default function InvestigationPanel() {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      {/* Header */}
      <div className="mb-5 flex items-center gap-2">
        <Brain className="text-cyan-400" size={20} />

        <h3 className="text-lg font-semibold text-white">
          AI Investigation
        </h3>
      </div>

      <div className="space-y-5">
        {/* Risk Score */}
        <div className="flex items-center justify-between">
          <span className="text-slate-400">Risk Score</span>

          <span className="rounded-full bg-red-500/20 px-3 py-1 text-sm font-semibold text-red-400">
            96%
          </span>
        </div>

        {/* Confidence */}
        <div className="flex items-center justify-between">
          <span className="text-slate-400">Confidence</span>

          <span className="rounded-full bg-emerald-500/20 px-3 py-1 text-sm font-semibold text-emerald-400">
            High
          </span>
        </div>

        {/* Attack Pattern */}
        <div className="flex items-center justify-between">
          <span className="text-slate-400">Attack Pattern</span>

          <span className="text-slate-200">
            Privilege Escalation
          </span>
        </div>

        {/* AI Assessment */}
        <div className="border-t border-slate-800 pt-5">
          <div className="mb-3 flex items-center gap-2">
            <ShieldAlert
              className="text-cyan-400"
              size={18}
            />

            <h4 className="font-medium text-white">
              AI Assessment
            </h4>
          </div>

          <p className="leading-7 text-slate-300">
            AI analysis indicates suspicious PowerShell
            execution following a successful credential
            compromise. The attacker attempted privilege
            escalation and lateral movement across
            multiple endpoints. Immediate containment
            is recommended while preserving forensic
            evidence.
          </p>
        </div>

        {/* AI Recommendation */}
        <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/10 p-4">
          <div className="mb-2 flex items-center gap-2">
            <TrendingUp
              className="text-cyan-400"
              size={18}
            />

            <span className="font-medium text-cyan-300">
              AI Recommendation
            </span>
          </div>

          <p className="text-sm leading-6 text-slate-300">
            • Isolate the affected endpoint.<br />
            • Disable compromised credentials.<br />
            • Initiate an EDR scan.<br />
            • Preserve forensic evidence before remediation.
          </p>
        </div>
      </div>
    </div>
  );
}