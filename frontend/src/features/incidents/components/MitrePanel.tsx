import { Shield } from "lucide-react";

const techniques = [
  {
    id: "T1059",
    name: "Command and Scripting Interpreter",
    tactic: "Execution",
  },
  {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "Initial Access",
  },
  {
    id: "T1068",
    name: "Exploitation for Privilege Escalation",
    tactic: "Privilege Escalation",
  },
  {
    id: "T1021",
    name: "Remote Services",
    tactic: "Lateral Movement",
  },
];

export default function MitrePanel() {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      <div className="mb-4 flex items-center gap-2">
        <Shield className="text-red-400" size={20} />
        <h3 className="text-lg font-semibold text-white">
          MITRE ATT&CK Mapping
        </h3>
      </div>

      <div className="space-y-3">
        {techniques.map((technique) => (
          <div
            key={technique.id}
            className="rounded-lg border border-slate-800 bg-slate-950 p-3"
          >
            <div className="flex items-center justify-between">
              <span className="font-semibold text-cyan-400">
                {technique.id}
              </span>

              <span className="rounded bg-red-500/20 px-2 py-1 text-xs text-red-400">
                {technique.tactic}
              </span>
            </div>

            <p className="mt-2 text-sm text-slate-300">
              {technique.name}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}