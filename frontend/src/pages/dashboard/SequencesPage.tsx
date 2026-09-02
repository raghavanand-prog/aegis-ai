import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Network } from "lucide-react";

import { EmptyState, ErrorState, LoadingState } from "@/components/ui";
import { usePermissions } from "@/features/auth/hooks/usePermissions";
import SignalBadge from "@/features/detection/components/SignalBadge";
import {
  dismissSequence,
  fetchCorrelationPatterns,
  fetchSequences,
  promoteSequence,
} from "@/services/api/sequences";
import type { ApiSequence } from "@/services/api/mlTypes";

/**
 * Correlated sequences: the queue of "several things happened together".
 *
 * A sequence is explicitly not an incident. Nothing is auto-promoted, because a
 * statistical grouping deciding on its own that the SOC has an incident is how
 * a queue becomes unusable. This page is where an analyst reads the grouping,
 * sees why it was made, and decides.
 */

const STATUS_FILTERS = ["Open", "Promoted", "Dismissed"] as const;

function SequenceRow({
  sequence,
  canPromote,
  busy,
  onPromote,
  onDismiss,
}: {
  sequence: ApiSequence;
  canPromote: boolean;
  busy: boolean;
  onPromote: () => void;
  onDismiss: () => void;
}) {
  return (
    <article className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 transition hover:border-slate-700">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Network size={15} className="text-emerald-400" />
            <h3 className="text-sm font-semibold text-white">{sequence.title}</h3>
            <span className="rounded-full bg-slate-800 px-2 py-0.5 text-[10px] uppercase tracking-wide text-slate-400">
              {sequence.status}
            </span>
          </div>
          <p className="mt-1 truncate font-mono text-[11px] text-slate-500">
            {sequence.id} · {sequence.pattern} · {sequence.correlationKey}
          </p>
        </div>

        <div className="shrink-0 text-right">
          <p className="text-xl font-bold text-white">{sequence.riskScore}</p>
          <p className="text-[11px] text-slate-500">
            {sequence.eventCount} events · confidence{" "}
            {sequence.confidence.toFixed(2)}
          </p>
        </div>
      </header>

      <p className="mt-3 text-sm leading-6 text-slate-400">{sequence.description}</p>

      {sequence.rationale.length > 0 && (
        <ul className="mt-3 space-y-1 rounded-lg bg-slate-950/60 p-3">
          {sequence.rationale.map((reason, index) => (
            <li key={index} className="text-xs leading-5 text-slate-400">
              · {reason}
            </li>
          ))}
        </ul>
      )}

      {sequence.riskSignals.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2">
          {sequence.riskSignals.map((signal, index) => (
            <SignalBadge
              key={index}
              kind={signal.type}
              detail={`+${signal.contribution}`}
              size="sm"
            />
          ))}
        </div>
      )}

      {sequence.incidentId ? (
        <p className="mt-4 text-xs text-slate-500">
          Promoted to{" "}
          <span className="font-mono text-cyan-400">{sequence.incidentId}</span>
        </p>
      ) : (
        canPromote &&
        sequence.status === "Open" && (
          <div className="mt-4 flex gap-2">
            <button
              onClick={onPromote}
              disabled={busy}
              className="flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-cyan-500 disabled:opacity-50"
            >
              {busy && <Loader2 size={12} className="animate-spin" />}
              Promote to incident
            </button>
            <button
              onClick={onDismiss}
              disabled={busy}
              className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-400 transition hover:bg-slate-800 disabled:opacity-50"
            >
              Dismiss
            </button>
          </div>
        )
      )}
    </article>
  );
}

export default function SequencesPage() {
  const [status, setStatus] = useState<(typeof STATUS_FILTERS)[number] | "All">("Open");
  const [busyId, setBusyId] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const { can } = usePermissions();

  const sequencesQuery = useQuery({
    queryKey: ["sequences", status],
    queryFn: () =>
      fetchSequences({ status: status === "All" ? undefined : status, limit: 50 }),
  });

  const patternsQuery = useQuery({
    queryKey: ["sequences", "patterns"],
    queryFn: fetchCorrelationPatterns,
  });

  const invalidate = () => {
    setBusyId(null);
    void queryClient.invalidateQueries({ queryKey: ["sequences"] });
    void queryClient.invalidateQueries({ queryKey: ["incidents"] });
  };

  const promoteMutation = useMutation({
    mutationFn: (sequenceId: string) => promoteSequence(sequenceId),
    onSettled: invalidate,
  });

  const dismissMutation = useMutation({
    mutationFn: (sequenceId: string) => dismissSequence(sequenceId),
    onSettled: invalidate,
  });

  const sequences = sequencesQuery.data?.items ?? [];

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-3xl font-bold text-white">Correlated Sequences</h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
          Groups of related events that individually look ordinary. A sequence
          is a finding, not an incident &mdash; nothing here is promoted
          automatically, because a statistical grouping deciding on its own that
          the SOC has an incident is how a queue becomes unusable.
        </p>
      </header>

      {patternsQuery.data && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
            Active correlation patterns
          </p>
          <ul className="mt-3 grid gap-3 sm:grid-cols-2">
            {patternsQuery.data.patterns.map((pattern) => (
              <li key={pattern.id} className="text-xs leading-5">
                <span className="font-mono text-emerald-400">{pattern.id}</span>{" "}
                <span className="text-slate-300">{pattern.name}</span>
                <p className="text-slate-500">{pattern.description}</p>
                {pattern.inferredTechniques.length > 0 && (
                  <p className="mt-0.5 text-slate-600">
                    infers {pattern.inferredTechniques.join(", ")}
                  </p>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        {(["All", ...STATUS_FILTERS] as const).map((option) => (
          <button
            key={option}
            onClick={() => setStatus(option)}
            className={`rounded-lg px-3 py-1.5 text-xs font-medium transition ${
              status === option
                ? "bg-cyan-600 text-white"
                : "border border-slate-700 text-slate-400 hover:bg-slate-800"
            }`}
          >
            {option}
          </button>
        ))}
      </div>

      {sequencesQuery.isLoading ? (
        <LoadingState label="Loading correlated sequences..." />
      ) : sequencesQuery.isError ? (
        <ErrorState
          error={sequencesQuery.error}
          onRetry={() => void sequencesQuery.refetch()}
        />
      ) : sequences.length === 0 ? (
        <EmptyState
          title="No correlated sequences"
          description={
            status === "Open"
              ? "The correlation engine has not grouped any related activity yet. Sequences appear when several events share a host, account or source address inside the correlation window."
              : `No sequences with status ${status}.`
          }
          icon={Network}
        />
      ) : (
        <div className="space-y-4">
          {sequences.map((sequence) => (
            <SequenceRow
              key={sequence.id}
              sequence={sequence}
              canPromote={can("incidents:create")}
              busy={busyId === sequence.id}
              onPromote={() => {
                setBusyId(sequence.id);
                promoteMutation.mutate(sequence.id);
              }}
              onDismiss={() => {
                setBusyId(sequence.id);
                dismissMutation.mutate(sequence.id);
              }}
            />
          ))}
        </div>
      )}
    </div>
  );
}
