import { useState } from "react";
import { Repeat } from "lucide-react";

import ErrorBoundary from "@/components/ErrorBoundary";
import { ErrorState, SkeletonBlock } from "@/components/ui";
import { useAuth } from "@/features/auth/hooks/useAuth";

import DriftPanel from "./components/DriftPanel";
import FeedbackPanel from "./components/FeedbackPanel";
import ProposalQueue from "./components/ProposalQueue";
import ReviewQueuePanel from "./components/ReviewQueuePanel";
import {
  useDriftStatus,
  useFeedback,
  useProposalActions,
  useProposals,
  useReviewQueue,
} from "./hooks/useAdaptation";

/**
 * Adaptive SOC.
 *
 * Where AEGISX shows what it has learned and what it would like to change —
 * and where a person decides. Nothing on this page applies itself.
 *
 * The framing throughout is deliberate. A drift reading is a statement about
 * the input distribution, not a verdict on the model. A review queue is a
 * suggestion about where attention is worth spending, not a list of findings.
 * A proposal is a request, and it says on its face when it has not been
 * validated. Each of those distinctions is easy to lose in a dashboard and
 * expensive to lose in a SOC.
 */

const TABS = ["Overview", "Feedback", "Drift", "Review queue", "Proposals"] as const;
type Tab = (typeof TABS)[number];

function Panel({ label, children }: { label: string; children: React.ReactNode }) {
  return <ErrorBoundary label={label}>{children}</ErrorBoundary>;
}

export default function AdaptivePage() {
  const { user } = useAuth();
  const [tab, setTab] = useState<Tab>("Overview");

  const feedback = useFeedback();
  const drift = useDriftStatus();
  const queue = useReviewQueue();
  const proposals = useProposals();
  const actions = useProposalActions();

  // The backend enforces this; hiding a button is a usability choice, never a
  // security control. A viewer who forges a request still gets a 403.
  const role = user?.role ?? "viewer";
  const canDecide = role === "admin";
  const canDeploy = role === "admin";

  const pendingCount =
    proposals.data?.filter((proposal) => proposal.status === "pending").length ?? 0;
  const significantDrift = drift.data?.countsByStatus?.significant ?? 0;

  if (feedback.isLoading || drift.isLoading || proposals.isLoading) {
    return (
      <div className="space-y-4 p-6">
        <SkeletonBlock className="h-8 w-64" />
        <SkeletonBlock className="h-40 w-full" />
      </div>
    );
  }

  if (feedback.isError || drift.isError || proposals.isError) {
    return (
      <div className="p-6">
        <ErrorState
          title="Adaptive SOC unavailable"
          error={feedback.error ?? drift.error ?? proposals.error}
          onRetry={() => {
            void feedback.refetch();
            void drift.refetch();
            void proposals.refetch();
          }}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <header>
        <div className="flex items-center gap-3">
          <Repeat className="h-6 w-6 text-cyan-400" />
          <h1 className="text-xl font-semibold text-slate-100">Adaptive SOC</h1>
        </div>
        <p className="mt-2 max-w-3xl text-sm text-slate-400">
          AEGISX may detect that its environment has changed, learn from analyst
          feedback, and propose an adaptation. It cannot apply one. Every change to
          what the platform detects is approved by a person and can be reversed.
        </p>
      </header>

      <nav className="flex flex-wrap gap-2" aria-label="Adaptive SOC sections">
        {TABS.map((name) => (
          <button
            key={name}
            type="button"
            onClick={() => setTab(name)}
            aria-current={tab === name ? "page" : undefined}
            className={`rounded border px-3 py-1.5 text-sm ${
              tab === name
                ? "border-cyan-500/40 bg-cyan-500/10 text-cyan-200"
                : "border-slate-700 text-slate-400 hover:text-slate-200"
            }`}
          >
            {name}
          </button>
        ))}
      </nav>

      {tab === "Overview" && (
        <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <article className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
            <p className="text-xs uppercase tracking-wide text-slate-500">Feedback</p>
            <p className="mt-1 text-2xl text-slate-100">{feedback.data?.length ?? 0}</p>
            <p className="mt-1 text-xs text-slate-500">current analyst claims</p>
          </article>
          <article className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
            <p className="text-xs uppercase tracking-wide text-slate-500">Pending proposals</p>
            <p className="mt-1 text-2xl text-slate-100">{pendingCount}</p>
            <p className="mt-1 text-xs text-slate-500">awaiting a human decision</p>
          </article>
          <article className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
            <p className="text-xs uppercase tracking-wide text-slate-500">Features drifting</p>
            <p className="mt-1 text-2xl text-slate-100">{significantDrift}</p>
            <p className="mt-1 text-xs text-slate-500">
              distribution changed — not a model failure
            </p>
          </article>
          <article className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
            <p className="text-xs uppercase tracking-wide text-slate-500">Queued for review</p>
            <p className="mt-1 text-2xl text-slate-100">
              {queue.data?.candidates.length ?? 0}
            </p>
            <p className="mt-1 text-xs text-slate-500">recommended, not labelled</p>
          </article>
        </section>
      )}

      {tab === "Feedback" && (
        <Panel label="Analyst feedback">
          <FeedbackPanel items={feedback.data ?? []} />
        </Panel>
      )}

      {tab === "Drift" && drift.data && (
        <Panel label="Feature drift">
          <DriftPanel data={drift.data} />
        </Panel>
      )}

      {tab === "Review queue" && queue.data && (
        <Panel label="Review queue">
          <ReviewQueuePanel data={queue.data} />
        </Panel>
      )}

      {tab === "Proposals" && (
        <Panel label="Adaptation proposals">
          <ProposalQueue
            proposals={proposals.data ?? []}
            canDecide={canDecide}
            canDeploy={canDeploy}
            pending={
              actions.approve.isPending ||
              actions.reject.isPending ||
              actions.deploy.isPending ||
              actions.rollback.isPending
            }
            onApprove={(id) => actions.approve.mutate(id)}
            onReject={(id, reason) => actions.reject.mutate({ id, reason })}
            onDeploy={(id) => actions.deploy.mutate(id)}
            onRollback={(id, reason) => actions.rollback.mutate({ id, reason })}
          />
        </Panel>
      )}
    </div>
  );
}
