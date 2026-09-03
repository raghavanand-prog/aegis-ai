import { useState } from "react";

import type { Proposal } from "@/services/api/adaptation";

import { PROPOSAL_STATUS_STYLE, statusText } from "./adaptiveFormat";

interface Props {
  proposals: Proposal[];
  canDecide: boolean;
  canDeploy: boolean;
  onApprove: (id: number) => void;
  onReject: (id: number, reason: string) => void;
  onDeploy: (id: number) => void;
  onRollback: (id: number, reason: string) => void;
  pending: boolean;
}

/**
 * The approval queue.
 *
 * Three deliberate choices:
 *
 * A proposal that has not been validated says so on its face. An approver
 * looking at a plausible title and a confident rationale has no other way to
 * tell that no evaluation was ever run.
 *
 * `selfApproved` is displayed rather than hidden. With three roles the same
 * administrator can propose and approve; showing it keeps the limitation
 * visible in the place where it matters.
 *
 * Rejection and rollback require a typed reason before the button does
 * anything, because the reason is the part that is worth reading later.
 */
export default function ProposalQueue({
  proposals,
  canDecide,
  canDeploy,
  onApprove,
  onReject,
  onDeploy,
  onRollback,
  pending,
}: Props) {
  const [reasons, setReasons] = useState<Record<number, string>>({});

  if (proposals.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-6">
        <p className="text-sm text-slate-300">No adaptation proposals have been raised.</p>
        <p className="mt-2 text-xs text-slate-500">
          Proposals are the only route from a signal to a change in what AEGISX
          detects. Nothing reaches production without one.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {proposals.map((proposal) => {
        const validated = proposal.validation?.status !== "not_validated";
        const gates = proposal.validation?.gates as { passed?: boolean } | undefined;
        const reason = reasons[proposal.id] ?? "";

        return (
          <article
            key={proposal.id}
            className="rounded-lg border border-slate-800 bg-slate-900/40 p-4"
          >
            <header className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="text-sm font-medium text-slate-100">{proposal.title}</h3>
                <p className="mt-1 font-mono text-xs text-slate-500">
                  {proposal.proposalType} · {proposal.affectedComponent}
                </p>
              </div>
              <span
                className={`rounded border px-2 py-1 text-xs ${
                  PROPOSAL_STATUS_STYLE[proposal.status] ?? ""
                }`}
              >
                {statusText(proposal.status)}
              </span>
            </header>

            <p className="mt-3 text-sm text-slate-300">{proposal.reason}</p>

            <dl className="mt-3 grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
              <div>
                <dt className="text-slate-500">Proposed by</dt>
                <dd className="font-mono text-slate-300">{proposal.proposedBy}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Approved by</dt>
                <dd className="font-mono text-slate-300">{proposal.approvedBy ?? "n/a"}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Before</dt>
                <dd className="font-mono text-slate-300">
                  {JSON.stringify(proposal.beforeState)}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">After</dt>
                <dd className="font-mono text-slate-300">
                  {JSON.stringify(proposal.afterState)}
                </dd>
              </div>
            </dl>

            <div className="mt-3 flex flex-wrap gap-2 text-xs">
              {!validated && (
                <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-amber-300">
                  Not validated — no evaluation has been run
                </span>
              )}
              {gates?.passed === false && (
                <span className="rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-rose-300">
                  Safety gates failed — cannot be approved
                </span>
              )}
              {proposal.selfApproved && (
                <span
                  className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-amber-300"
                  title="The same person proposed and approved this adaptation."
                >
                  Self-approved
                </span>
              )}
              {proposal.proposedBy.startsWith("ai:") && (
                <span className="rounded border border-slate-600 px-2 py-1 text-slate-400">
                  AI-drafted — advisory only
                </span>
              )}
            </div>

            {proposal.riskAssessment && (
              <p className="mt-3 text-xs text-slate-400">{proposal.riskAssessment}</p>
            )}

            {(canDecide || canDeploy) && proposal.status !== "rolled_back" && (
              <div className="mt-4 flex flex-wrap items-center gap-2">
                {canDecide && proposal.status === "pending" && (
                  <>
                    <button
                      type="button"
                      disabled={pending || gates?.passed === false}
                      onClick={() => onApprove(proposal.id)}
                      className="rounded border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 text-xs text-cyan-200 disabled:opacity-40"
                    >
                      Approve
                    </button>
                    <input
                      value={reason}
                      onChange={(event) =>
                        setReasons({ ...reasons, [proposal.id]: event.target.value })
                      }
                      placeholder="Reason (required to reject)"
                      aria-label={`Reason for proposal ${proposal.id}`}
                      className="min-w-[16rem] flex-1 rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs text-slate-200"
                    />
                    <button
                      type="button"
                      disabled={pending || reason.trim().length === 0}
                      onClick={() => onReject(proposal.id, reason)}
                      className="rounded border border-slate-600 px-3 py-1.5 text-xs text-slate-300 disabled:opacity-40"
                    >
                      Reject
                    </button>
                  </>
                )}
                {canDeploy && proposal.status === "approved" && (
                  <button
                    type="button"
                    disabled={pending}
                    onClick={() => onDeploy(proposal.id)}
                    className="rounded border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs text-emerald-200 disabled:opacity-40"
                  >
                    Deploy
                  </button>
                )}
                {canDeploy && proposal.status === "deployed" && (
                  <>
                    <input
                      value={reason}
                      onChange={(event) =>
                        setReasons({ ...reasons, [proposal.id]: event.target.value })
                      }
                      placeholder="Reason (required to roll back)"
                      aria-label={`Rollback reason for proposal ${proposal.id}`}
                      className="min-w-[16rem] flex-1 rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs text-slate-200"
                    />
                    <button
                      type="button"
                      disabled={pending || reason.trim().length === 0}
                      onClick={() => onRollback(proposal.id, reason)}
                      className="rounded border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 text-xs text-rose-200 disabled:opacity-40"
                    >
                      Roll back
                    </button>
                  </>
                )}
              </div>
            )}
          </article>
        );
      })}
    </div>
  );
}
