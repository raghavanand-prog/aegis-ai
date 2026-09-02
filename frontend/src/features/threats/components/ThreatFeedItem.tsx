import { AlertTriangle } from "lucide-react";

interface Props {
  title: string;
  severity: string;
  source: string;
  time: string;
}

export default function ThreatFeedItem({
  title,
  severity,
  source,
  time,
}: Props) {
  const color = {
    Critical: "text-red-400 bg-red-500/10",
    High: "text-orange-400 bg-orange-500/10",
    Medium: "text-yellow-300 bg-yellow-500/10",
    Low: "text-blue-400 bg-blue-500/10",
  };

  return (
    <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 p-4 transition hover:border-cyan-500/40">
      <div className="flex items-center gap-4">
        <AlertTriangle className="h-5 w-5 text-cyan-400" />

        <div>
          <h3 className="font-medium text-white">{title}</h3>

          <p className="text-sm text-slate-400">
            {source}
          </p>
        </div>
      </div>

      <div className="text-right">
        <span
          className={`rounded-full px-3 py-1 text-xs ${
            color[severity as keyof typeof color]
          }`}
        >
          {severity}
        </span>

        <p className="mt-2 text-xs text-slate-500">
          {time}
        </p>
      </div>
    </div>
  );
}