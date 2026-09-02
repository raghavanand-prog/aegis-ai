import { BrainCircuit } from "lucide-react";

export default function ThreatSummary() {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
      <div className="mb-4 flex items-center gap-3">
        <BrainCircuit className="h-6 w-6 text-cyan-400" />
        <h2 className="text-xl font-semibold text-white">
          AI Threat Summary
        </h2>
      </div>

      <p className="leading-7 text-slate-300">
        Multiple phishing domains and known command-and-control IP addresses
        have been detected in the last 24 hours. Two indicators are classified
        as <span className="text-red-400 font-medium">Critical</span> based on
        threat intelligence feeds. Immediate blocking and further investigation
        are recommended.
      </p>
    </div>
  );
}