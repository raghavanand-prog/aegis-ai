import { Globe, Loader2, ShieldQuestion } from "lucide-react";

import UnavailablePanel from "@/features/detection/components/UnavailablePanel";
import type { ApiThreatIntelStatus } from "@/services/api/mlTypes";
import type { IndicatorIntel } from "@/services/api/threatIntel";
import type { ApiIOC } from "@/services/api/types";

/**
 * Indicators and their external reputation.
 *
 * Two states are kept strictly apart, because conflating them turns an outage
 * into a clean bill of health:
 *
 *   "no verdict was obtained"  (status !== ok)
 *   "the provider says this is harmless"
 */

const REPUTATION_STYLES: Record<string, string> = {
  malicious: "border-red-500/40 bg-red-500/10 text-red-300",
  suspicious: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  harmless: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  unknown: "border-slate-600/50 bg-slate-700/30 text-slate-400",
};

interface IntelTabProps {
  iocs: ApiIOC[];
  intel: Record<string, IndicatorIntel>;
  status: ApiThreatIntelStatus | undefined;
  canEnrich: boolean;
  enrichingValue: string | null;
  onEnrich: (value: string, type: string) => void;
}

export default function IntelTab({
  iocs,
  intel,
  status,
  canEnrich,
  enrichingValue,
  onEnrich,
}: IntelTabProps) {
  return (
    <div className="space-y-5">
      {status && !status.configured && (
        <UnavailablePanel
          title="No threat intelligence provider is configured"
          reason={
            status.provider === "none"
              ? "THREAT_INTEL_PROVIDER is not set, so no external reputation is available. Indicators below have unknown reputation - which is not the same as being clean."
              : `${status.provider} is selected but has no API key configured.`
          }
          hint="THREAT_INTEL_PROVIDER=virustotal  VIRUSTOTAL_API_KEY=..."
        />
      )}

      {iocs.length === 0 ? (
        <p className="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 px-5 py-10 text-center text-sm text-slate-500">
          No indicators were extracted from this incident&apos;s events.
        </p>
      ) : (
        <ul className="space-y-3">
          {iocs.map((ioc) => {
            const entry = intel[ioc.value];
            const verdicts = entry?.results ?? [];
            const notLookedUp = entry?.notLookedUp ?? null;
            const actionable = verdicts.filter((verdict) => verdict.isActionable);
            const failed = verdicts.filter((verdict) => !verdict.isActionable);

            return (
              <li
                key={ioc.id}
                className="rounded-xl border border-slate-800 bg-slate-900/60 p-4"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="font-mono text-sm text-slate-200">{ioc.value}</p>
                    <p className="mt-0.5 text-xs text-slate-500">
                      {ioc.type} · seen {ioc.sightingCount}x · first{" "}
                      {new Date(ioc.firstSeen).toLocaleDateString()}
                    </p>
                  </div>

                  {canEnrich && status?.configured && !notLookedUp && (
                    <button
                      onClick={() => onEnrich(ioc.value, ioc.type)}
                      disabled={enrichingValue === ioc.value}
                      className="flex shrink-0 items-center gap-1.5 rounded-lg border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-xs text-amber-200 transition hover:bg-amber-500/20 disabled:opacity-50"
                    >
                      {enrichingValue === ioc.value ? (
                        <Loader2 size={11} className="animate-spin" />
                      ) : (
                        <Globe size={11} />
                      )}
                      Look up
                    </button>
                  )}
                </div>

                {actionable.length > 0 && (
                  <ul className="mt-3 space-y-2">
                    {actionable.map((verdict) => (
                      <li
                        key={verdict.provider}
                        className="flex flex-wrap items-center gap-2 rounded-lg bg-slate-950/60 px-3 py-2 text-xs"
                      >
                        <span
                          className={`rounded-full border px-2 py-0.5 font-medium ${
                            REPUTATION_STYLES[verdict.reputation] ??
                            REPUTATION_STYLES.unknown
                          }`}
                        >
                          {verdict.reputation}
                        </span>
                        <span className="text-slate-400">{verdict.provider}</span>
                        <span className="text-slate-500">
                          {verdict.maliciousCount} malicious ·{" "}
                          {verdict.suspiciousCount} suspicious ·{" "}
                          {verdict.harmlessCount} harmless
                        </span>
                        {verdict.lookedUpAt && (
                          <span className="ml-auto text-slate-600">
                            {new Date(verdict.lookedUpAt).toLocaleString()}
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                )}

                {failed.map((verdict) => (
                  <p
                    key={`${verdict.provider}-failed`}
                    className="mt-3 flex items-start gap-1.5 rounded-lg bg-slate-950/60 px-3 py-2 text-xs leading-5 text-slate-500"
                  >
                    <ShieldQuestion size={12} className="mt-0.5 shrink-0" />
                    <span>
                      <span className="text-slate-400">{verdict.provider}</span>{" "}
                      returned no verdict ({verdict.status}
                      {verdict.error ? `: ${verdict.error}` : ""}). Reputation is
                      unknown, not clean.
                    </span>
                  </p>
                ))}

                {notLookedUp ? (
                  <p className="mt-3 flex items-start gap-1.5 rounded-lg bg-slate-950/60 px-3 py-2 text-xs leading-5 text-slate-500">
                    <ShieldQuestion size={12} className="mt-0.5 shrink-0" />
                    <span>
                      Not looked up externally. {notLookedUp}
                    </span>
                  </p>
                ) : (
                  verdicts.length === 0 && (
                    <p className="mt-3 text-xs text-slate-500">
                      No external reputation has been looked up for this indicator.
                    </p>
                  )
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
