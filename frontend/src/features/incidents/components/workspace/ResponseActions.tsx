import { useState } from "react";
import { AlertTriangle, Check, ShieldAlert, X } from "lucide-react";

import { Button } from "@/components/ui";
import type {
  ApiResponseAction,
  ApiResponseActionList,
  ResponseActionType,
} from "@/services/api/responseActions";

/**
 * Requesting containment, and a second person deciding on it.
 *
 * The important thing this panel must never imply is that anything happened to
 * a real system. AEGISX records the decision and stops: there is no executor,
 * no provider, no result. Every request and every approval says so, in the
 * response payload and on screen.
 *
 * The four-eyes rule is the backend's - an approver may not be the requester,
 * and approving needs `incidents:respond_approve`, which analysts do not hold.
 * The controls below are hidden or disabled to match, but that is usability
 * only: the same request forged by hand is refused by the service layer.
 *
 * Approving sends the evidence manifest the workspace actually rendered. If the
 * evidence moved between the page loading and the click, the server refuses
 * with 409 and the message is shown verbatim - it is the one that says what to
 * do next.
 */

const ACTION_TYPES: { value: ResponseActionType; label: string }[] = [
  { value: "isolate_endpoint", label: "Isolate endpoint" },
  { value: "disable_account", label: "Disable account" },
  { value: "block_indicator", label: "Block indicator" },
  { value: "revoke_session", label: "Revoke session" },
  { value: "quarantine_file", label: "Quarantine file" },
];

const STATUS_STYLES: Record<string, string> = {
  requested: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  approved: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  rejected: "border-slate-600/40 bg-slate-700/30 text-slate-300",
  withdrawn: "border-slate-600/40 bg-slate-700/30 text-slate-400",
};

function ActionRow({
  action,
  canDecide,
  currentUserEmail,
  onApprove,
  onReject,
  isSubmitting,
  error,
}: {
  action: ApiResponseAction;
  canDecide: boolean;
  currentUserEmail: string | undefined;
  onApprove: (ref: string, reason: string) => void;
  onReject: (ref: string, reason: string) => void;
  isSubmitting: boolean;
  error: string | null;
}) {
  const [reason, setReason] = useState("");
  const [open, setOpen] = useState(false);

  // Four-eyes, mirrored from the backend rule so the UI does not offer a button
  // that will always be refused. Folded for case, as the server folds it.
  const isOwnRequest =
    currentUserEmail !== undefined &&
    currentUserEmail.trim().toLowerCase() ===
      action.requestedBy.trim().toLowerCase();
  const decidable = action.status === "requested" && canDecide && !isOwnRequest;

  return (
    <li className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
      <div className="mb-1.5 flex flex-wrap items-start justify-between gap-2">
        <p className="min-w-0 flex-1 text-sm text-slate-200">
          {ACTION_TYPES.find((item) => item.value === action.actionType)?.label ??
            action.actionType}
        </p>
        <span
          className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-medium ${
            STATUS_STYLES[action.status] ?? STATUS_STYLES.withdrawn
          }`}
        >
          {action.status}
        </span>
      </div>

      <p className="text-[11px] italic text-slate-400">
        “{action.justification}”
      </p>
      <p className="mt-1 text-[11px] text-slate-500">
        {action.requestedBy} · {new Date(action.requestedAt).toLocaleString()}
      </p>

      {Object.keys(action.parameters).length > 0 && (
        <p className="mt-1 font-mono text-[10px] text-slate-500">
          {Object.entries(action.parameters)
            .map(([key, value]) => `${key}=${String(value)}`)
            .join(" · ")}
        </p>
      )}

      {action.decidedBy && (
        <p className="mt-1.5 text-[11px] text-slate-400">
          {action.status === "approved" ? "Approved" : "Refused"} by{" "}
          {action.decidedBy}
          {action.decidedByRole ? ` (${action.decidedByRole})` : ""}
          {action.decisionReason ? ` — ${action.decisionReason}` : ""}
        </p>
      )}

      {action.status === "approved" && (
        <p className="mt-1.5 flex items-start gap-1.5 rounded border border-slate-700/60 bg-slate-950/60 px-2 py-1.5 text-[10px] text-slate-400">
          <ShieldAlert size={12} className="mt-0.5 shrink-0 text-amber-400" />
          Approved and <span className="font-medium">not executed</span>. AEGISX
          records the decision; nothing was carried out against any system.
        </p>
      )}

      {action.decisionRef && (
        <p className="mt-1 font-mono text-[10px] text-slate-600">
          {action.requestRef} · evidence {action.decisionRef}
        </p>
      )}
      {!action.decisionRef && (
        <p className="mt-1 font-mono text-[10px] text-slate-600">
          {action.requestRef}
        </p>
      )}

      {action.status === "requested" && isOwnRequest && canDecide && (
        <p className="mt-2 text-[11px] text-slate-500">
          You raised this request, so you cannot also decide it. A containment
          action needs a second person.
        </p>
      )}

      {decidable && !open && (
        <div className="mt-2">
          <Button type="button" variant="secondary" onClick={() => setOpen(true)}>
            Decide
          </Button>
        </div>
      )}

      {decidable && open && (
        <div className="mt-2 space-y-2">
          <textarea
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            rows={2}
            placeholder="Reason (required to refuse; optional to approve)"
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyan-600 focus:outline-none"
          />
          {error && (
            <p className="flex items-start gap-1.5 rounded border border-red-500/30 bg-red-500/5 px-2 py-1.5 text-[11px] text-red-300">
              <AlertTriangle size={12} className="mt-0.5 shrink-0" />
              {error}
            </p>
          )}
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              disabled={isSubmitting}
              onClick={() => onApprove(action.requestRef, reason)}
            >
              <span className="inline-flex items-center gap-1">
                <Check size={13} /> Approve
              </span>
            </Button>
            <Button
              type="button"
              variant="danger"
              disabled={isSubmitting || reason.trim().length === 0}
              onClick={() => onReject(action.requestRef, reason)}
            >
              <span className="inline-flex items-center gap-1">
                <X size={13} /> Refuse
              </span>
            </Button>
          </div>
        </div>
      )}
    </li>
  );
}

interface Props {
  actions: ApiResponseActionList | undefined;
  isLoading: boolean;
  isError: boolean;
  canRequest: boolean;
  canDecide: boolean;
  currentUserEmail: string | undefined;
  isSubmitting: boolean;
  error: string | null;
  onRequest: (input: {
    actionType: ResponseActionType;
    parameters: Record<string, unknown>;
    justification: string;
  }) => void;
  onApprove: (ref: string, reason: string) => void;
  onReject: (ref: string, reason: string) => void;
}

export default function ResponseActions({
  actions,
  isLoading,
  isError,
  canRequest,
  canDecide,
  currentUserEmail,
  isSubmitting,
  error,
  onRequest,
  onApprove,
  onReject,
}: Props) {
  const [actionType, setActionType] = useState<ResponseActionType>(
    "isolate_endpoint",
  );
  const [target, setTarget] = useState("");
  const [justification, setJustification] = useState("");
  const [composing, setComposing] = useState(false);

  if (isLoading) {
    return (
      <p className="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 px-4 py-6 text-center text-sm text-slate-500">
        Loading response actions…
      </p>
    );
  }

  const usable = actions !== undefined && Array.isArray(actions.items);

  if (isError || !usable) {
    return (
      <p className="rounded-xl border border-dashed border-red-900/50 bg-red-950/20 px-4 py-6 text-center text-sm text-red-300">
        Response actions could not be loaded. This is not the same as there being
        none — nothing is claimed either way.
      </p>
    );
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-2">
        <p className="text-[11px] leading-5 text-slate-400">
          <span className="font-medium text-slate-300">
            Nothing here is executed.
          </span>{" "}
          A request records what somebody wants done; approving it records that a
          second, authorised person agreed and which evidence they agreed on.
          AEGISX carries out no action against any system in this version.
        </p>
      </div>

      {canRequest && !composing && (
        <Button type="button" variant="secondary" onClick={() => setComposing(true)}>
          Request containment
        </Button>
      )}

      {canRequest && composing && (
        <div className="space-y-2 rounded-lg border border-slate-800 bg-slate-900/60 p-3">
          <label className="block">
            <span className="text-xs text-slate-400">Action</span>
            <select
              value={actionType}
              onChange={(event) =>
                setActionType(event.target.value as ResponseActionType)
              }
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 focus:border-cyan-600 focus:outline-none"
            >
              {ACTION_TYPES.map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>

          <label className="block">
            <span className="text-xs text-slate-400">Target</span>
            <input
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="Host, account or indicator"
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyan-600 focus:outline-none"
            />
          </label>

          <label className="block">
            <span className="text-xs text-slate-400">
              Justification <span className="text-amber-300">— required</span>
            </span>
            <textarea
              value={justification}
              onChange={(event) => setJustification(event.target.value)}
              rows={2}
              placeholder="What makes this warranted? An approver weighs this."
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyan-600 focus:outline-none"
            />
          </label>

          {error && (
            <p className="flex items-start gap-1.5 rounded border border-red-500/30 bg-red-500/5 px-2 py-1.5 text-[11px] text-red-300">
              <AlertTriangle size={12} className="mt-0.5 shrink-0" />
              {error}
            </p>
          )}

          <div className="flex gap-2">
            <Button
              type="button"
              disabled={isSubmitting || justification.trim().length === 0}
              onClick={() => {
                onRequest({
                  actionType,
                  parameters: target.trim() ? { target: target.trim() } : {},
                  justification,
                });
                setComposing(false);
                setTarget("");
                setJustification("");
              }}
            >
              Raise request
            </Button>
            <Button
              type="button"
              variant="ghost"
              onClick={() => setComposing(false)}
            >
              Cancel
            </Button>
          </div>
        </div>
      )}

      {actions.items.length === 0 ? (
        <p className="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 px-4 py-6 text-center text-sm text-slate-500">
          No containment action has been requested for this incident.
        </p>
      ) : (
        <ul className="space-y-2">
          {actions.items.map((action) => (
            <ActionRow
              key={action.requestRef}
              action={action}
              canDecide={canDecide}
              currentUserEmail={currentUserEmail}
              onApprove={onApprove}
              onReject={onReject}
              isSubmitting={isSubmitting}
              error={error}
            />
          ))}
        </ul>
      )}
    </div>
  );
}
