import { useQuery } from "@tanstack/react-query";
import { CloudCog, FlaskConical } from "lucide-react";

import { fetchCloudFindings } from "@/services/api/cloud";
import type { ApiCloudFinding } from "@/services/api/cloud";

/**
 * Cloud misconfigurations AEGISX knows about.
 *
 * The banner is not decoration. Nothing in this project has scanned a real
 * cloud account: findings are computed by local checks from configuration
 * snapshots committed to this repository, and a reader who took them for real
 * would be drawing conclusions about infrastructure that does not exist. The
 * text comes from the backend's own `note` rather than being written here, so
 * there is one statement of what this is rather than two that could drift.
 *
 * Severity orders the queue and is not a risk score. A public bucket holding
 * public data is not a critical problem, and AEGISX cannot know what is in the
 * bucket - so these are never summed, averaged, or turned into a posture
 * grade.
 */

const SEVERITY_TONE: Record<string, string> = {
  Critical: "border-red-500/30 bg-red-500/10 text-red-300",
  High: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  Medium: "border-yellow-500/20 bg-yellow-500/10 text-yellow-200",
  Low: "border-slate-600/40 bg-slate-700/30 text-slate-300",
};

function FindingRow({ finding }: { finding: ApiCloudFinding }) {
  const { resource } = finding;
  return (
    <li className="rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2.5">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <p className="min-w-0 flex-1 text-sm text-slate-200">{finding.title}</p>
        <span
          className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-medium ${
            SEVERITY_TONE[finding.severity] ?? SEVERITY_TONE.Low
          }`}
        >
          {finding.severity}
        </span>
      </div>

      <p className="mt-1 text-[11px] leading-5 text-slate-400">{finding.description}</p>

      <p className="mt-1.5 font-mono text-[10px] text-slate-500">
        {resource.service}:{resource.resourceType || "—"}/{resource.resourceId}
        {resource.region ? ` · ${resource.region}` : ""} · account {resource.account || "—"}
      </p>

      <p className="mt-1 text-[10px] text-slate-600">
        {finding.checkId}
        {finding.control ? ` · ${finding.control}` : ""}
      </p>
    </li>
  );
}

export default function CloudPosturePanel() {
  const query = useQuery({
    queryKey: ["cloud", "findings"],
    queryFn: () => fetchCloudFindings({ limit: 50 }),
  });

  if (query.isLoading) {
    return (
      <p className="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 px-4 py-6 text-center text-sm text-slate-500">
        Loading cloud posture…
      </p>
    );
  }

  const data = query.data;
  const usable = data !== undefined && Array.isArray(data.items);

  if (query.isError || !usable) {
    return (
      <p className="rounded-xl border border-dashed border-red-900/50 bg-red-950/20 px-4 py-6 text-center text-sm text-red-300">
        Cloud posture could not be loaded, so nothing is known about it here.
        This is not the same as there being no findings.
      </p>
    );
  }

  return (
    <section className="space-y-3">
      <div>
        <h2 className="flex items-center gap-2 text-lg font-semibold text-white">
          <CloudCog size={18} className="text-cyan-400" />
          Cloud posture
        </h2>
        <p className="mt-1 max-w-2xl text-sm text-slate-400">
          Misconfigurations found by local checks. Severity orders this queue and
          is not a risk score — AEGISX cannot know what a bucket holds.
        </p>
      </div>

      <p className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-[11px] leading-5 text-amber-200">
        <FlaskConical size={13} className="mt-0.5 shrink-0" />
        {data.note}
      </p>

      {data.items.length === 0 ? (
        <p className="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 px-4 py-6 text-center text-sm text-slate-500">
          No posture scan has been recorded. That means nothing has been looked
          at, not that nothing is wrong.
        </p>
      ) : (
        <>
          <p className="text-xs text-slate-500">
            {data.total} finding{data.total === 1 ? "" : "s"}, worst first.
          </p>
          <ul className="space-y-2">
            {data.items.map((finding) => (
              <FindingRow key={finding.findingId} finding={finding} />
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
