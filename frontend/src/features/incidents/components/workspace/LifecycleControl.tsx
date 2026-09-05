import { useState } from "react";
import { AlertTriangle, Lock, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui";
import type {
  ApiIncidentTransitions,
  ApiTransitionOption,
} from "@/services/api/incidents";

/**
 * Moving an incident through its lifecycle.
 *
 * Until now the workspace had no status control at all, which is why the
 * evidence-freshness protection built in Phase D had never been reachable by a
 * click: `useUpdateIncident` attaches the manifest digest the workspace
 * rendered, and nothing called it.
 *
 * Two things this component deliberately does not do:
 *
 * It does not decide which transitions are legal. That graph, which edges need
 * a reason and which need which permission all live in the backend's
 * `lifecycle.py`, and are fetched from `/incidents/{id}/transitions`. A second
 * copy in TypeScript would drift, and the copy that drifts is the one users
 * see.
 *
 * It does not hide the transitions this user may not take. They are shown
 * disabled, naming the authority they need. Hiding them would teach an analyst
 * that closing an incident is not a thing the system does, rather than that it
 * is a thing somebody else does.
 */

interface Props {
  transitions: ApiIncidentTransitions | undefined;
  isLoading: boolean;
  isError: boolean;
  isSubmitting: boolean;
  /** Server-supplied refusal, shown verbatim - it explains what to do next. */
  error: string | null;
  onTransition: (target: string, reason: string) => void;
}

function TransitionButton({
  option,
  selected,
  onSelect,
}: {
  option: ApiTransitionOption;
  selected: boolean;
  onSelect: () => void;
}) {
  if (!option.permitted) {
    return (
      <span
        title={`Requires ${option.requiredPermission}. Your role does not hold it.`}
        className="inline-flex cursor-not-allowed items-center gap-1 rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-1.5 text-xs text-slate-600"
      >
        <Lock size={12} />
        {option.target}
      </span>
    );
  }

  return (
    <button
      type="button"
      onClick={onSelect}
      className={`inline-flex items-center gap-1 rounded-lg border px-3 py-1.5 text-xs transition ${
        selected
          ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-200"
          : "border-slate-700 bg-slate-900 text-slate-300 hover:border-slate-600 hover:text-white"
      }`}
    >
      {option.bindsEvidence && <ShieldCheck size={12} />}
      {option.target}
    </button>
  );
}

export default function LifecycleControl({
  transitions,
  isLoading,
  isError,
  isSubmitting,
  error,
  onTransition,
}: Props) {
  const [target, setTarget] = useState<string | null>(null);
  const [reason, setReason] = useState("");

  if (isLoading) {
    return <p className="text-xs text-slate-500">Loading lifecycle…</p>;
  }

  const usable =
    transitions !== undefined && Array.isArray(transitions.options);

  if (isError || !usable) {
    return (
      <p className="text-xs text-red-300">
        The lifecycle could not be loaded, so no transition is offered. This does
        not mean none is possible.
      </p>
    );
  }

  if (transitions.isTerminal) {
    return (
      <p className="flex items-center gap-1.5 text-xs text-slate-500">
        <Lock size={12} />
        This incident is {transitions.currentStatus} and sealed. Reopening one
        would rewrite a decision somebody signed — raise a new incident instead.
      </p>
    );
  }

  const chosen = transitions.options.find((option) => option.target === target);
  const reasonRequired = chosen?.requiresReason ?? false;
  const canSubmit =
    chosen !== undefined &&
    !isSubmitting &&
    (!reasonRequired || reason.trim().length > 0);

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mr-1 text-xs text-slate-500">Move to</span>
        {transitions.options.map((option) => (
          <TransitionButton
            key={option.target}
            option={option}
            selected={option.target === target}
            onSelect={() => {
              setTarget(option.target === target ? null : option.target);
              setReason("");
            }}
          />
        ))}
      </div>

      {chosen && (
        <div className="space-y-2 rounded-lg border border-slate-800 bg-slate-900/60 p-3">
          <label className="block">
            <span className="text-xs text-slate-400">
              Reason{" "}
              {reasonRequired ? (
                <span className="text-amber-300">
                  — required: this ends or undoes recorded work
                </span>
              ) : (
                <span className="text-slate-600">— optional</span>
              )}
            </span>
            <textarea
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              rows={2}
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyan-600 focus:outline-none"
              placeholder={
                reasonRequired
                  ? "Why is this being resolved, closed, or reopened?"
                  : "Optional note"
              }
            />
          </label>

          {chosen.bindsEvidence && (
            <p className="flex items-start gap-1.5 text-[11px] text-slate-500">
              <ShieldCheck size={12} className="mt-0.5 shrink-0 text-cyan-400" />
              This decision is recorded against the evidence currently shown. If
              that evidence has changed since the page loaded, the transition is
              refused rather than taken on a stale view.
            </p>
          )}

          {error && (
            <p className="flex items-start gap-1.5 rounded border border-red-500/30 bg-red-500/5 px-2 py-1.5 text-[11px] text-red-300">
              <AlertTriangle size={12} className="mt-0.5 shrink-0" />
              {error}
            </p>
          )}

          <Button
            type="button"
            disabled={!canSubmit}
            onClick={() => onTransition(chosen.target, reason)}
          >
            {isSubmitting ? "Recording…" : `Move to ${chosen.target}`}
          </Button>
        </div>
      )}
    </div>
  );
}
