import { Shield } from "lucide-react";

const tactics = [
  {
    name: "Initial Access",
    technique: "Phishing (T1566)",
    color: "bg-red-500",
  },
  {
    name: "Execution",
    technique: "PowerShell (T1059)",
    color: "bg-orange-500",
  },
  {
    name: "Persistence",
    technique: "Registry Run Keys (T1547)",
    color: "bg-yellow-500",
  },
  {
    name: "Credential Access",
    technique: "Credential Dumping (T1003)",
    color: "bg-cyan-500",
  },
  {
    name: "Lateral Movement",
    technique: "Remote Services (T1021)",
    color: "bg-purple-500",
  },
];

export default function MitreCard() {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
      <div className="mb-6 flex items-center gap-3">
        <Shield className="h-6 w-6 text-cyan-400" />

        <h2 className="text-xl font-semibold text-white">
          MITRE ATT&CK Coverage
        </h2>
      </div>

      <div className="space-y-4">
        {tactics.map((item) => (
          <div
            key={item.name}
            className="rounded-lg border border-slate-800 bg-slate-950 p-4 transition hover:border-cyan-500/40"
          >
            <div className="mb-2 flex items-center justify-between">
              <span className="font-medium text-white">
                {item.name}
              </span>

              <span
                className={`h-2 w-2 rounded-full ${item.color}`}
              />
            </div>

            <p className="text-sm text-slate-400">
              {item.technique}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}