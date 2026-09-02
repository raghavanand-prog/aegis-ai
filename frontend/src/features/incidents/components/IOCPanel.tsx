import { ShieldCheck } from "lucide-react";

const iocs = [
  {
    type: "IP Address",
    value: "185.199.110.23",
    reputation: "Malicious",
  },
  {
    type: "Domain",
    value: "secure-login-update.net",
    reputation: "Suspicious",
  },
  {
    type: "File Hash",
    value: "3f786850e387550fdab836ed7e6dc881de23001b",
    reputation: "Malicious",
  },
  {
    type: "Process",
    value: "powershell.exe",
    reputation: "Observed",
  },
];

export default function IOCPanel() {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      <div className="mb-5 flex items-center gap-2">
        <ShieldCheck className="text-cyan-400" size={20} />
        <h3 className="text-lg font-semibold text-white">
          Indicators of Compromise
        </h3>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-slate-700 text-slate-400">
              <th className="pb-3">Type</th>
              <th className="pb-3">Value</th>
              <th className="pb-3">Reputation</th>
            </tr>
          </thead>

          <tbody>
            {iocs.map((ioc, index) => (
              <tr
                key={index}
                className="border-b border-slate-800"
              >
                <td className="py-3">{ioc.type}</td>

                <td className="py-3 font-mono text-cyan-300">
                  {ioc.value}
                </td>

                <td className="py-3">
                  <span className="rounded bg-red-500/20 px-2 py-1 text-xs text-red-400">
                    {ioc.reputation}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}