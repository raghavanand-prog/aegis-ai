import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  Bot,
  Clock,
  Crosshair,
  FileText,
  Globe,
  Layers,
  Network,
  Sparkles,
  X,
} from "lucide-react";

import { ErrorState, LoadingState } from "@/components/ui";
import { usePermissions } from "@/features/auth/hooks/usePermissions";
import RiskBreakdown from "@/features/detection/components/RiskBreakdown";
import { fetchAIAnalyses, fetchAIStatus, requestAIAnalysis } from "@/services/api/ai";
import type { AIAnalysisKind } from "@/services/api/ai";
import { api } from "@/services/api/client";
import { fetchIncidentMLFindings, fetchMLStatus } from "@/services/api/ml";
import {
  enrichIndicator,
  fetchIndicatorIntel,
  fetchThreatIntelStatus,
} from "@/services/api/threatIntel";
import type { IndicatorIntel } from "@/services/api/threatIntel";
import type { ApiIncident } from "@/services/api/types";

import AIAnalystPanel from "../AIAnalystPanel";
import EvidenceTab from "./EvidenceTab";
import IntelTab from "./IntelTab";
import MitreTab from "./MitreTab";
import SequenceTab from "./SequenceTab";

/**
 * The investigation workspace.
 *
 * This replaces the V1 incident drawer, which rendered hard-coded evidence,
 * hard-coded IOCs, a hard-coded timeline and a hard-coded "AI" paragraph. Every
 * panel here reads the live backend, and every panel that can legitimately be
 * empty says why it is empty.
 *
 * The tab order follows how an incident is actually worked: what is it, when
 * did it happen, what is the evidence, what do the indicators say, how does it
 * map to ATT&CK, what did the model think, what does the AI make of it, and
 * finally the raw record.
 */

const TABS = [
  { id: "overview", label: "Overview", icon: Layers },
  { id: "timeline", label: "Timeline", icon: Clock },
  { id: "evidence", label: "Evidence", icon: Activity },
  { id: "intel", label: "Threat Intel", icon: Globe },
  { id: "correlation", label: "Correlation", icon: Network },
  { id: "mitre", label: "MITRE", icon: Crosshair },
  { id: "ai", label: "AI Analyst", icon: Bot },
  { id: "raw", label: "Raw", icon: FileText },
] as const;

type TabId = (typeof TABS)[number]["id"];

interface WorkspaceProps {
  incidentId: string | null;
  open: boolean;
  onClose: () => void;
}

export default function InvestigationWorkspace({
  incidentId,
  open,
  onClose,
}: WorkspaceProps) {
  const [tab, setTab] = useState<TabId>("overview");
  const [enriching, setEnriching] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const { can } = usePermissions();

  const enabled = Boolean(open && incidentId);

  const incidentQuery = useQuery({
    queryKey: ["incident", incidentId],
    queryFn: async () => {
      const { data } = await api.get<ApiIncident>(`/incidents/${incidentId}`);
      return data;
    },
    enabled,
  });

  const mlQuery = useQuery({
    queryKey: ["incident", incidentId, "ml"],
    queryFn: () => fetchIncidentMLFindings(incidentId as string),
    enabled,
  });

  const mlStatusQuery = useQuery({
    queryKey: ["ml", "status"],
    queryFn: fetchMLStatus,
    enabled,
  });

  const aiStatusQuery = useQuery({
    queryKey: ["ai", "status"],
    queryFn: fetchAIStatus,
    enabled,
  });

  const aiQuery = useQuery({
    queryKey: ["incident", incidentId, "ai"],
    queryFn: () => fetchAIAnalyses(incidentId as string),
    enabled,
  });

  const intelStatusQuery = useQuery({
    queryKey: ["threat-intel", "status"],
    queryFn: fetchThreatIntelStatus,
    enabled,
  });

  const incident = incidentQuery.data;

  // Cached verdicts for this incident's indicators, fetched together so the
  // panel can distinguish "no verdict" from "clean".
  const intelQuery = useQuery({
    queryKey: ["incident", incidentId, "intel", incident?.iocs?.length ?? 0],
    queryFn: async () => {
      const entries = await Promise.all(
        (incident?.iocs ?? []).map(async (ioc) => {
          const intel = await fetchIndicatorIntel(ioc.value, ioc.type);
          return [ioc.value, intel] as const;
        }),
      );
      return Object.fromEntries(entries) as Record<string, IndicatorIntel>;
    },
    enabled: enabled && Boolean(incident?.iocs?.length),
  });

  const aiMutation = useMutation({
    mutationFn: ({ kind, question }: { kind: AIAnalysisKind; question?: string }) =>
      requestAIAnalysis(incidentId as string, kind, question),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["incident", incidentId, "ai"] });
      void queryClient.invalidateQueries({ queryKey: ["ai", "status"] });
    },
  });

  const enrichMutation = useMutation({
    mutationFn: ({ value, type }: { value: string; type: string }) =>
      enrichIndicator(value, type),
    onSettled: () => {
      setEnriching(null);
      void queryClient.invalidateQueries({ queryKey: ["incident", incidentId, "intel"] });
    },
  });

  const anomalyCount = incident?.mlAnomalyCount ?? 0;
  const sequences = useMemo(() => incident?.sequences ?? [], [incident]);

  const badges: Partial<Record<TabId, number>> = {
    evidence: incident?.events?.length ?? 0,
    intel: incident?.iocs?.length ?? 0,
    correlation: sequences.length,
    ai: aiQuery.data?.total ?? 0,
  };

  if (!open || !incidentId) return null;

  return (
    <>
      <div
        className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />

      <aside className="fixed right-0 top-0 z-50 flex h-screen w-full max-w-4xl flex-col border-l border-slate-800 bg-slate-950 shadow-2xl">
        {/* --- Header ---------------------------------------------------- */}
        <div className="border-b border-slate-800 bg-slate-950/95 p-6 pb-0 backdrop-blur">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <p className="text-xs uppercase tracking-widest text-cyan-400">
                Investigation Workspace
              </p>
              <h2 className="mt-2 truncate text-2xl font-bold text-white">
                {incident?.title ?? incidentId}
              </h2>

              <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
                <span className="rounded bg-slate-800 px-2.5 py-1 font-mono text-slate-300">
                  {incidentId}
                </span>
                {incident && (
                  <>
                    <span className="rounded bg-red-500/20 px-2.5 py-1 text-red-300">
                      {incident.severity}
                    </span>
                    <span className="rounded bg-emerald-500/20 px-2.5 py-1 text-emerald-300">
                      {incident.status}
                    </span>
                    <span className="rounded bg-cyan-500/20 px-2.5 py-1 text-cyan-300">
                      {incident.analyst}
                    </span>
                    {anomalyCount > 0 && (
                      <span className="flex items-center gap-1 rounded bg-violet-500/20 px-2.5 py-1 text-violet-300">
                        <Sparkles size={11} />
                        {anomalyCount} ML anomal{anomalyCount === 1 ? "y" : "ies"}
                      </span>
                    )}
                  </>
                )}
              </div>
            </div>

            <button
              onClick={onClose}
              aria-label="Close investigation workspace"
              className="shrink-0 rounded-lg border border-slate-700 p-2 text-slate-400 transition hover:bg-slate-800 hover:text-white"
            >
              <X size={18} />
            </button>
          </div>

          {/* --- Tabs ---------------------------------------------------- */}
          <nav className="mt-5 flex gap-1 overflow-x-auto" role="tablist">
            {TABS.map((entry) => {
              const Icon = entry.icon;
              const badge = badges[entry.id];
              const active = tab === entry.id;
              return (
                <button
                  key={entry.id}
                  role="tab"
                  aria-selected={active}
                  onClick={() => setTab(entry.id)}
                  className={`flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-2.5 text-xs font-medium transition ${
                    active
                      ? "border-cyan-400 text-cyan-300"
                      : "border-transparent text-slate-500 hover:text-slate-300"
                  }`}
                >
                  <Icon size={13} />
                  {entry.label}
                  {badge != null && badge > 0 && (
                    <span className="rounded-full bg-slate-800 px-1.5 text-[10px] text-slate-400">
                      {badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* --- Body ------------------------------------------------------ */}
        <div className="flex-1 overflow-y-auto p-6">
          {incidentQuery.isLoading ? (
            <LoadingState label="Loading incident..." />
          ) : incidentQuery.isError || !incident ? (
            <ErrorState
              error={incidentQuery.error}
              onRetry={() => void incidentQuery.refetch()}
            />
          ) : (
            <>
              {tab === "overview" && (
                <div className="space-y-6">
                  <RiskBreakdown
                    score={incident.riskScore}
                    level={incident.severity}
                    signals={incident.riskSignals ?? []}
                  />

                  <section>
                    <h3 className="text-sm font-semibold text-white">Description</h3>
                    <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-slate-400">
                      {incident.description || "No description recorded."}
                    </p>
                  </section>

                  <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                    {[
                      ["Events", incident.eventCount],
                      ["Indicators", incident.iocs?.length ?? 0],
                      ["Sequences", sequences.length],
                      ["ML anomalies", anomalyCount],
                    ].map(([label, value]) => (
                      <div
                        key={label as string}
                        className="rounded-lg border border-slate-800 bg-slate-900/60 p-3"
                      >
                        <dt className="text-xs text-slate-500">{label}</dt>
                        <dd className="mt-1 text-xl font-semibold text-white">
                          {value as number}
                        </dd>
                      </div>
                    ))}
                  </dl>

                  {mlStatusQuery.data && !mlStatusQuery.data.available && (
                    <p className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-xs leading-5 text-slate-500">
                      <span className="text-slate-400">ML detection is not active.</span>{" "}
                      {mlStatusQuery.data.reason}
                    </p>
                  )}
                </div>
              )}

              {tab === "timeline" && (
                <ol className="space-y-3">
                  {(incident.timeline ?? []).length === 0 ? (
                    <p className="text-sm text-slate-500">
                      No timeline entries recorded.
                    </p>
                  ) : (
                    incident.timeline.map((entry, index) => (
                      <li
                        key={index}
                        className="rounded-lg border border-slate-800 bg-slate-900/60 p-3"
                      >
                        <div className="flex flex-wrap items-baseline justify-between gap-2">
                          <span className="text-sm font-medium text-white">
                            {entry.action.replace(/_/g, " ")}
                          </span>
                          <span className="font-mono text-[11px] text-slate-500">
                            {new Date(entry.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <p className="mt-1 text-sm text-slate-400">{entry.detail}</p>
                        <p className="mt-1 text-[11px] text-slate-600">
                          by {entry.actor}
                        </p>
                      </li>
                    ))
                  )}
                </ol>
              )}

              {tab === "evidence" && (
                <EvidenceTab incident={incident} ml={mlQuery.data} />
              )}

              {tab === "intel" && (
                <IntelTab
                  iocs={incident.iocs ?? []}
                  intel={intelQuery.data ?? {}}
                  status={intelStatusQuery.data}
                  canEnrich={can("threatintel:enrich")}
                  enrichingValue={enriching}
                  onEnrich={(value, type) => {
                    setEnriching(value);
                    enrichMutation.mutate({ value, type });
                  }}
                />
              )}

              {tab === "correlation" && <SequenceTab sequences={sequences} />}

              {tab === "mitre" && (
                <MitreTab incident={incident} sequences={sequences} />
              )}

              {tab === "ai" && (
                <AIAnalystPanel
                  status={aiStatusQuery.data}
                  analyses={aiQuery.data?.analyses ?? []}
                  isLoading={aiQuery.isLoading}
                  isRequesting={aiMutation.isPending}
                  error={aiMutation.error}
                  canRequest={can("ai:request")}
                  onRequest={(kind, question) => aiMutation.mutate({ kind, question })}
                />
              )}

              {tab === "raw" && (
                <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900 p-4 text-xs leading-5 text-slate-400">
                  {JSON.stringify(incident, null, 2)}
                </pre>
              )}
            </>
          )}
        </div>
      </aside>
    </>
  );
}
