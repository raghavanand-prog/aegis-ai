import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, CircleSlash, Globe, HardDrive } from "lucide-react";

import { fetchProviders } from "@/services/api/providers";
import type { ApiProvider } from "@/services/api/providers";

/**
 * Which evidence sources are answering.
 *
 * The per-incident evidence panel already names providers that were degraded
 * when that incident was collected. This is the same fact asked ahead of time,
 * because "the anomaly model has not been loaded since the service started" is
 * not something an analyst should discover from a footnote halfway through an
 * investigation.
 *
 * Deliberately not a control panel. There is no enable, disable, reconfigure
 * or retry here, and no endpoint behind one - V9 reports on providers, it does
 * not operate them.
 *
 * This is also not in the top status banner. A missing anomaly model does not
 * make what is on screen stale or wrong; it makes it narrower. Putting it in
 * the banner alongside "database unavailable" would train people to dismiss
 * the banner, which is the failure mode that costs the most.
 */

const TONE: Record<string, { chip: string; icon: ReactNode }> = {
  healthy: {
    chip: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
    icon: <CheckCircle2 size={13} className="text-emerald-400" />,
  },
  degraded: {
    chip: "border-amber-500/30 bg-amber-500/10 text-amber-300",
    icon: <AlertTriangle size={13} className="text-amber-400" />,
  },
  unavailable: {
    chip: "border-red-500/30 bg-red-500/10 text-red-300",
    icon: <CircleSlash size={13} className="text-red-400" />,
  },
};

function ProviderRow({ provider }: { provider: ApiProvider }) {
  const tone = TONE[provider.health.status] ?? TONE.unavailable;

  return (
    <li className="flex flex-wrap items-start justify-between gap-3 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2.5">
      <div className="min-w-0 flex-1">
        <p className="flex items-center gap-1.5 font-mono text-sm text-slate-200">
          {provider.isExternal ? (
            <Globe size={12} className="shrink-0 text-cyan-400" />
          ) : (
            <HardDrive size={12} className="shrink-0 text-slate-500" />
          )}
          {provider.name}
        </p>
        <p className="mt-0.5 text-[11px] text-slate-500">
          {provider.produces.length > 0
            ? provider.produces.join(", ")
            : "produces nothing"}
          {provider.isExternal ? " · reaches outside the platform" : " · local projection"}
        </p>
        {provider.health.reason && (
          <p className="mt-1 text-[11px] text-slate-400">{provider.health.reason}</p>
        )}
      </div>
      <span
        className={`inline-flex shrink-0 items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium ${tone.chip}`}
      >
        {tone.icon}
        {provider.health.status}
      </span>
    </li>
  );
}

export default function ProviderHealthPanel() {
  const query = useQuery({
    queryKey: ["providers"],
    queryFn: fetchProviders,
    refetchInterval: 60_000,
  });

  if (query.isLoading) {
    return (
      <p className="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 px-4 py-6 text-center text-sm text-slate-500">
        Loading evidence sources…
      </p>
    );
  }

  const data = query.data;
  const usable = data !== undefined && Array.isArray(data.providers);

  if (query.isError || !usable) {
    return (
      <p className="rounded-xl border border-dashed border-red-900/50 bg-red-950/20 px-4 py-6 text-center text-sm text-red-300">
        The evidence sources could not be loaded, so their state is unknown. This
        is not the same as them being healthy.
      </p>
    );
  }

  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-lg font-semibold text-white">Evidence sources</h2>
        <p className="mt-1 max-w-2xl text-sm text-slate-400">
          Every source AEGISX collects investigation evidence from. A degraded
          source returns nothing, which is not the same as finding nothing —
          this is where that difference is visible before an investigation
          rather than after it.
        </p>
      </div>

      <p className="text-xs text-slate-500">
        {data.degraded === 0
          ? `All ${data.total} sources are answering.`
          : `${data.degraded} of ${data.total} sources ${
              data.degraded === 1 ? "is" : "are"
            } not fully available.`}
      </p>

      <ul className="space-y-2">
        {data.providers.map((provider) => (
          <ProviderRow key={provider.name} provider={provider} />
        ))}
      </ul>

      <p className="text-[11px] text-slate-600">
        Read-only. AEGISX reports on its providers and does not enable, disable
        or reconfigure them.
      </p>
    </section>
  );
}
