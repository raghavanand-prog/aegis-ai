import { AlertCircle, Info } from "lucide-react";

/**
 * The empty state for an optional subsystem.
 *
 * The distinction this component exists to preserve: "the model found nothing"
 * and "no model is running" produce the same empty list, and showing the same
 * blank panel for both is how a SOC dashboard starts lying to its analysts.
 * Every V3 panel that can be empty for a reason renders this with the reason
 * the backend gave, verbatim.
 */

interface UnavailablePanelProps {
  title: string;
  /** The backend's own explanation. Never invented here. */
  reason?: string | null;
  hint?: string;
  tone?: "info" | "warning";
}

export default function UnavailablePanel({
  title,
  reason,
  hint,
  tone = "info",
}: UnavailablePanelProps) {
  const Icon = tone === "warning" ? AlertCircle : Info;

  return (
    <div
      className={`rounded-xl border p-5 ${
        tone === "warning"
          ? "border-amber-500/30 bg-amber-500/5"
          : "border-slate-800 bg-slate-900/60"
      }`}
    >
      <div className="flex items-start gap-3">
        <Icon
          size={18}
          className={tone === "warning" ? "text-amber-400" : "text-slate-500"}
        />
        <div className="min-w-0">
          <p className="text-sm font-semibold text-white">{title}</p>
          {reason && (
            <p className="mt-1.5 text-sm leading-6 text-slate-400">{reason}</p>
          )}
          {hint && (
            <p className="mt-2 rounded-lg bg-slate-950/70 px-3 py-2 font-mono text-xs text-slate-400">
              {hint}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
