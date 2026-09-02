import { X, ShieldAlert, Clock, Activity } from "lucide-react";

type Threat = {
  id: string;
  threat: string;
  severity: string;
  status: string;
  time: string;
};

type Props = {
  threat: Threat | null;
  onClose: () => void;
};

function ThreatDetailsDrawer({ threat, onClose }: Props) {
  if (!threat) return null;

  const severityColor = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  };

  const statusColor = {
    active: "bg-red-500/20 text-red-400 border-red-500/30",
    investigating: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    open: "bg-slate-500/20 text-slate-300 border-slate-500/30",
    resolved: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm">
      <div className="absolute right-0 top-0 h-full w-[430px] bg-slate-950 border-l border-slate-800 shadow-2xl overflow-y-auto">

        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 p-6">
          <div>
            <h2 className="text-2xl font-bold text-white">
              Threat Details
            </h2>

            <p className="mt-1 text-sm text-slate-400">
              Security incident overview
            </p>
          </div>

          <button
            onClick={onClose}
            className="rounded-lg p-2 text-slate-400 transition hover:bg-slate-800 hover:text-white"
          >
            <X size={22} />
          </button>
        </div>

        {/* Content */}
        <div className="space-y-6 p-6">

          {/* Threat Info */}
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">

            <div className="flex items-center gap-3">
              <ShieldAlert className="text-red-400" size={24} />

              <div>
                <p className="text-sm text-slate-400">
                  Threat
                </p>

                <h3 className="text-lg font-semibold text-white">
                  {threat.threat}
                </h3>
              </div>
            </div>

            <div className="mt-6 grid gap-5">

              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Severity
                </p>

                <span
                  className={`mt-2 inline-block rounded-full border px-3 py-1 text-sm font-medium ${
                    severityColor[
                      threat.severity.toLowerCase() as keyof typeof severityColor
                    ]
                  }`}
                >
                  {threat.severity.toUpperCase()}
                </span>
              </div>

              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500">
                  Status
                </p>

                <span
                  className={`mt-2 inline-block rounded-full border px-3 py-1 text-sm font-medium ${
                    statusColor[
                      threat.status.toLowerCase() as keyof typeof statusColor
                    ]
                  }`}
                >
                  {threat.status.toUpperCase()}
                </span>
              </div>

              <div className="flex items-center gap-2">
                <Clock size={18} className="text-slate-500" />

                <div>
                  <p className="text-xs uppercase tracking-wide text-slate-500">
                    Detected At
                  </p>

                  <p className="text-white">
                    {threat.time}
                  </p>
                </div>
              </div>

            </div>

          </div>

          {/* AI Analysis */}
          <div className="rounded-xl border border-blue-500/20 bg-blue-500/10 p-5">

            <div className="mb-3 flex items-center gap-2">
              <Activity className="text-blue-400" size={20} />

              <h3 className="font-semibold text-white">
                AI Analysis
              </h3>
            </div>

            <p className="leading-7 text-slate-300">
              This activity matches a known attack pattern.
              Immediate investigation is recommended to determine
              whether exploitation was successful. Review logs,
              identify the affected assets and isolate compromised
              systems if required.
            </p>

          </div>

          {/* Recommended Actions */}
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">

            <h3 className="mb-4 text-lg font-semibold text-white">
              Recommended Actions
            </h3>

            <ul className="space-y-3 text-slate-300">

              <li>✅ Block the source IP address.</li>

              <li>✅ Review authentication logs.</li>

              <li>✅ Inspect affected systems.</li>

              <li>✅ Notify the SOC team.</li>

              <li>✅ Enable additional monitoring.</li>

            </ul>

          </div>

        </div>

      </div>
    </div>
  );
}

export default ThreatDetailsDrawer;