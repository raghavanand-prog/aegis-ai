/**
 * The visual vocabulary for the five kinds of evidence AEGISX produces.
 *
 * Kept in its own module, separate from the components that render it, so a
 * component file exports components only.
 *
 * The requirement this exists for: an analyst must never have to guess whether
 * a finding came from a deterministic rule, a statistical model, an external
 * vendor, a correlation, or an LLM. Each gets its own colour, icon and word,
 * used identically everywhere, so "why is this high risk?" is answerable at a
 * glance rather than by reading a paragraph.
 *
 * Colours are assigned by meaning, not decoration:
 *   rule         cyan     deterministic, explainable, our own logic
 *   ml           violet   statistical, ranked, no notion of a technique
 *   threat_intel amber    someone else's opinion about an indicator
 *   correlation  emerald  a pattern across events, not a property of one
 *   context      slate    a minor nudge, never a finding on its own
 *   ai           fuchsia  interpretation of the above, never detection
 */

import { Bot, Braces, Clock, Globe, Network, Sparkles } from "lucide-react";
import type { LucideIcon } from "lucide-react";

import type { RiskSignalType } from "@/services/api/mlTypes";

export type SignalKind = RiskSignalType | "ai";

export interface SignalStyle {
  label: string;
  short: string;
  icon: LucideIcon;
  className: string;
  dot: string;
  /** One line an analyst can read to know what this kind of evidence *is*. */
  meaning: string;
}

export const SIGNAL_STYLES: Record<SignalKind, SignalStyle> = {
  rule: {
    label: "Rule Detection",
    short: "Rule",
    icon: Braces,
    className: "border-cyan-500/30 bg-cyan-500/10 text-cyan-300",
    dot: "bg-cyan-400",
    meaning:
      "A hand-written, versioned rule matched and stated the condition it matched. Deterministic and explainable.",
  },
  ml: {
    label: "ML Anomaly",
    short: "ML",
    icon: Sparkles,
    className: "border-violet-500/30 bg-violet-500/10 text-violet-300",
    dot: "bg-violet-400",
    meaning:
      "An unsupervised model ranked this behaviour as unusual against its learned baseline. Unusual is not malicious, and the model identifies no attack technique.",
  },
  threat_intel: {
    label: "External Reputation",
    short: "Intel",
    icon: Globe,
    className: "border-amber-500/30 bg-amber-500/10 text-amber-300",
    dot: "bg-amber-400",
    meaning:
      "A third-party reputation service returned a verdict on an indicator. Independent corroboration, and one vendor's opinion.",
  },
  correlation: {
    label: "Behavioural Sequence",
    short: "Correlation",
    icon: Network,
    className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
    dot: "bg-emerald-400",
    meaning:
      "Several related events were grouped by a correlation pattern. The pattern is the finding; no single event here is notable.",
  },
  context: {
    label: "Event Context",
    short: "Context",
    icon: Clock,
    className: "border-slate-600/50 bg-slate-700/30 text-slate-300",
    dot: "bg-slate-400",
    meaning:
      "A minor contextual nudge such as off-hours timing. Deliberately small - a hint, not a finding.",
  },
  ai: {
    label: "AI Analyst",
    short: "AI",
    icon: Bot,
    className: "border-fuchsia-500/30 bg-fuchsia-500/10 text-fuchsia-300",
    dot: "bg-fuchsia-400",
    meaning:
      "AI-generated interpretation of the evidence above. Not a detector, and not a determination by the platform.",
  },
};
