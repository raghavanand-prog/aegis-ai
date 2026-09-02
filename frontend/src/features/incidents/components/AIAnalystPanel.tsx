import { useState } from "react";
import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  ChevronDown,
  FileSearch,
  Link2,
  Loader2,
  ShieldQuestion,
  Sparkles,
} from "lucide-react";

import { ErrorState } from "@/components/ui";
import type { ApiAIAnalysis, ApiAIStatus } from "@/services/api/mlTypes";
import type { AIAnalysisKind } from "@/services/api/ai";

import UnavailablePanel from "@/features/detection/components/UnavailablePanel";

/**
 * The AI analyst surface.
 *
 * This is a SOC copilot, not a chatbot, and the layout enforces that:
 *
 * - Every answer is stamped AI-generated, with the provider, model and prompt
 *   version it came from.
 * - Grounding warnings render *above* the text, not in a footnote. If the model
 *   cited something the evidence does not contain, the analyst sees that first.
 * - Claims are shown next to the evidence identifier they point at, so a
 *   statement can be traced back to an event, a rule or a sequence.
 * - "Insufficient evidence" is rendered as a legitimate answer rather than as
 *   an empty state.
 * - The template provider is labelled as such, so a deterministic answer is
 *   never mistaken for model output.
 */

interface AIAnalystPanelProps {
  status: ApiAIStatus | undefined;
  analyses: ApiAIAnalysis[];
  isLoading: boolean;
  isRequesting: boolean;
  error: unknown;
  canRequest: boolean;
  onRequest: (kind: AIAnalysisKind, question?: string) => void;
}

const ACTIONS: { kind: AIAnalysisKind; label: string; hint: string }[] = [
  {
    kind: "analyze",
    label: "Explain this incident",
    hint: "Full analysis of what happened and what it is consistent with",
  },
  {
    kind: "explain",
    label: "Why is the risk this high?",
    hint: "Walks the risk score signal by signal",
  },
  {
    kind: "recommend",
    label: "Suggest next steps",
    hint: "Investigation and containment actions, grounded in this evidence",
  },
];

const CONFIDENCE_STYLES: Record<string, string> = {
  high: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  medium: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  low: "border-slate-600/50 bg-slate-700/30 text-slate-300",
  insufficient_evidence: "border-slate-600/50 bg-slate-800/50 text-slate-400",
  unknown: "border-slate-600/50 bg-slate-800/50 text-slate-400",
};

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  if (!children) return null;
  return (
    <div>
      <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
        {title}
      </p>
      <div className="mt-1.5 text-sm leading-6 text-slate-300">{children}</div>
    </div>
  );
}

function AnalysisCard({ analysis }: { analysis: ApiAIAnalysis }) {
  const [showRaw, setShowRaw] = useState(false);
  const confidenceLabel =
    analysis.confidence === "insufficient_evidence"
      ? "Insufficient evidence"
      : analysis.confidence;

  return (
    <article className="rounded-xl border border-fuchsia-500/20 bg-slate-900/70 p-5">
      {/* --- Provenance header. Never optional. --------------------------- */}
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <Bot size={16} className="text-fuchsia-400" />
          <span className="text-sm font-semibold text-white">AI Analysis</span>
          <span className="rounded-full border border-fuchsia-500/30 bg-fuchsia-500/10 px-2 py-0.5 text-[11px] text-fuchsia-300">
            {analysis.kind}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
          <span
            className={`rounded-full border px-2 py-0.5 ${
              CONFIDENCE_STYLES[analysis.confidence] ?? CONFIDENCE_STYLES.unknown
            }`}
            title="The model's own stated confidence. Not a calibrated value."
          >
            {confidenceLabel}
          </span>
          <span>
            {analysis.provider}
            {analysis.model ? ` · ${analysis.model}` : ""}
          </span>
          <span>prompt v{analysis.promptVersion}</span>
        </div>
      </header>

      {/* --- Grounding. Above the text, deliberately. --------------------- */}
      {analysis.grounded ? (
        <p className="mt-3 flex items-center gap-1.5 text-xs text-emerald-400/80">
          <CheckCircle2 size={12} />
          Every claim checked against the evidence package this was generated
          from.
        </p>
      ) : (
        <div className="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3">
          <p className="flex items-center gap-1.5 text-xs font-semibold text-amber-300">
            <AlertTriangle size={13} />
            This analysis made claims the evidence does not support
          </p>
          <ul className="mt-2 space-y-1 text-xs leading-5 text-amber-200/80">
            {analysis.groundingWarnings.map((warning, index) => (
              <li key={index}>· {warning}</li>
            ))}
          </ul>
          <p className="mt-2 text-[11px] text-amber-200/60">
            Shown rather than hidden: discarding it would conceal the failure,
            accepting it silently would conceal the fabrication.
          </p>
        </div>
      )}

      {analysis.isTemplateProvider && (
        <p className="mt-3 flex items-center gap-1.5 rounded-lg bg-slate-950/70 px-3 py-2 text-[11px] text-slate-400">
          <ShieldQuestion size={12} />
          Generated by the built-in deterministic template analyst, not a
          language model. Set <code className="text-slate-300">AI_PROVIDER</code>{" "}
          and <code className="text-slate-300">AI_API_KEY</code> to use one.
        </p>
      )}

      {/* --- The analysis itself ------------------------------------------ */}
      <div className="mt-4 space-y-4">
        <Section title="Summary">{analysis.summary}</Section>
        <Section title="Why it matters">{analysis.whyItMatters}</Section>
        <Section title="Risk assessment">{analysis.riskAssessment}</Section>
        <Section title="Likely behaviour (interpretation)">
          {analysis.likelyBehaviour}
        </Section>

        {analysis.supportingEvidence.length > 0 && (
          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
              Claims and the evidence behind them
            </p>
            <ul className="mt-2 space-y-2">
              {analysis.supportingEvidence.map((entry, index) => (
                <li
                  key={index}
                  className="rounded-lg border border-slate-800 bg-slate-950/60 p-3"
                >
                  <p className="text-sm leading-6 text-slate-300">
                    {entry.claim}
                  </p>
                  <p className="mt-1.5 flex items-center gap-1.5 font-mono text-[11px] text-cyan-400">
                    <Link2 size={11} />
                    {entry.evidenceRef}
                  </p>
                </li>
              ))}
            </ul>
          </div>
        )}

        {analysis.mitreTechniques.length > 0 && (
          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
              MITRE ATT&amp;CK
            </p>
            <ul className="mt-2 space-y-1.5">
              {analysis.mitreTechniques.map((technique) => (
                <li
                  key={technique.technique}
                  className="flex flex-wrap items-baseline gap-2 text-sm text-slate-300"
                >
                  <span className="rounded border border-purple-500/30 bg-purple-500/10 px-2 py-0.5 font-mono text-xs text-purple-300">
                    {technique.technique}
                  </span>
                  <span
                    className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-slate-400"
                    title="mapped = a rule declared it; inferred = correlation derived it; contextual = present on a member event"
                  >
                    {technique.provenance}
                  </span>
                  <span className="text-xs text-slate-500">
                    {technique.rationale}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {analysis.investigationSteps.length > 0 && (
          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
              Suggested investigation steps
            </p>
            <ol className="mt-2 space-y-1.5">
              {analysis.investigationSteps.map((step, index) => (
                <li key={index} className="flex gap-2 text-sm leading-6 text-slate-300">
                  <span className="text-slate-600">{index + 1}.</span>
                  {step}
                </li>
              ))}
            </ol>
          </div>
        )}

        {analysis.containmentActions.length > 0 && (
          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
              Suggested containment
            </p>
            <ul className="mt-2 space-y-1.5">
              {analysis.containmentActions.map((action, index) => (
                <li key={index} className="text-sm leading-6 text-slate-300">
                  · {action}
                </li>
              ))}
            </ul>
            <p className="mt-2 text-[11px] text-slate-500">
              Suggestions for a human to weigh. AEGISX records response actions
              and executes nothing automatically.
            </p>
          </div>
        )}

        <Section title="What could not be determined">
          {analysis.uncertainty}
        </Section>
      </div>

      {/* --- Footer ------------------------------------------------------- */}
      <footer className="mt-4 border-t border-slate-800 pt-3">
        <p className="text-[11px] leading-5 text-slate-500">{analysis.disclaimer}</p>
        <button
          onClick={() => setShowRaw((value) => !value)}
          className="mt-2 flex items-center gap-1 text-[11px] text-slate-500 transition hover:text-slate-300"
        >
          <ChevronDown
            size={11}
            className={showRaw ? "rotate-180 transition" : "transition"}
          />
          Provenance
        </button>
        {showRaw && (
          <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-[11px] text-slate-500">
            <dt>evidence fingerprint</dt>
            <dd className="text-slate-400">{analysis.evidenceFingerprint}</dd>
            <dt>analysis version</dt>
            <dd className="text-slate-400">{analysis.analysisVersion}</dd>
            <dt>requested by</dt>
            <dd className="text-slate-400">{analysis.requestedBy}</dd>
            <dt>latency</dt>
            <dd className="text-slate-400">{analysis.latencyMs.toFixed(0)} ms</dd>
            {analysis.tokensUsed > 0 && (
              <>
                <dt>tokens</dt>
                <dd className="text-slate-400">{analysis.tokensUsed}</dd>
              </>
            )}
            <dt>evidence seen</dt>
            <dd className="text-slate-400">
              {Object.entries(analysis.evidenceSummary)
                .filter(([, value]) => value > 0)
                .map(([key, value]) => `${key}:${value}`)
                .join(" ") || "none"}
            </dd>
          </dl>
        )}
      </footer>
    </article>
  );
}

export default function AIAnalystPanel({
  status,
  analyses,
  isLoading,
  isRequesting,
  error,
  canRequest,
  onRequest,
}: AIAnalystPanelProps) {
  const [question, setQuestion] = useState("");

  if (status && !status.available) {
    return (
      <UnavailablePanel
        title="AI analyst unavailable"
        reason={status.reason}
        hint={
          status.provider === "none"
            ? "AI_ENABLED=true and AI_PROVIDER=mock enables the offline analyst."
            : "Set AI_API_KEY in the backend environment."
        }
      />
    );
  }

  return (
    <div className="space-y-5">
      {/* --- Controls ----------------------------------------------------- */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Sparkles size={16} className="text-fuchsia-400" />
            <h3 className="text-sm font-semibold text-white">Ask the AI analyst</h3>
          </div>
          {status && (
            <p className="text-[11px] text-slate-500">
              {status.provider}
              {status.isTemplateProvider && " (offline template)"}
              {status.sendsDataExternally && (
                <span className="ml-2 text-amber-400/80">
                  sends incident detail to {status.provider}
                </span>
              )}
              {" · "}
              {status.budget.remaining} of {status.budget.limit} requests left today
            </p>
          )}
        </div>

        <p className="mt-2 text-xs leading-5 text-slate-500">
          The analyst sees only this incident&apos;s evidence package &mdash;
          events, rule findings, ML findings, indicators, threat intelligence and
          correlated sequences. It has no other knowledge of this environment and
          no ability to look anything up.
        </p>

        <textarea
          rows={2}
          value={question}
          onChange={(event) => setQuestion(event.target.value.slice(0, 500))}
          disabled={!canRequest || isRequesting}
          placeholder="Optional: ask something specific about this incident..."
          className="mt-4 w-full resize-none rounded-lg border border-slate-700 bg-slate-950 p-3 text-sm text-white outline-none transition focus:border-fuchsia-500 disabled:opacity-50"
        />

        <div className="mt-3 flex flex-wrap gap-2">
          {ACTIONS.map((action) => (
            <button
              key={action.kind}
              title={action.hint}
              disabled={!canRequest || isRequesting}
              onClick={() => onRequest(action.kind, question.trim() || undefined)}
              className="flex items-center gap-1.5 rounded-lg border border-fuchsia-500/30 bg-fuchsia-500/10 px-3 py-2 text-xs font-medium text-fuchsia-200 transition hover:bg-fuchsia-500/20 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {isRequesting ? (
                <Loader2 size={13} className="animate-spin" />
              ) : (
                <FileSearch size={13} />
              )}
              {action.label}
            </button>
          ))}
        </div>

        {!canRequest && (
          <p className="mt-3 text-xs text-slate-500">
            Your role can read existing analyses but not request new ones &mdash;
            a request spends budget and, with a hosted provider, sends incident
            detail outside this deployment.
          </p>
        )}
      </div>

      {error != null && <ErrorState error={error} title="The AI analyst could not answer" />}

      {/* --- Results ------------------------------------------------------ */}
      {isLoading ? (
        <p className="text-sm text-slate-500">Loading stored analyses...</p>
      ) : analyses.length === 0 ? (
        <p className="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 px-5 py-8 text-center text-sm text-slate-500">
          No AI analysis has been requested for this incident yet.
        </p>
      ) : (
        <div className="space-y-4">
          {analyses.map((analysis) => (
            <AnalysisCard key={analysis.id} analysis={analysis} />
          ))}
        </div>
      )}
    </div>
  );
}
