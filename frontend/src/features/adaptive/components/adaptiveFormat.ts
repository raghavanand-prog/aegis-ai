/**
 * Formatting rules for the adaptive views.
 *
 * The rule inherited from V4: an absent number renders as `n/a`, never as 0%.
 * A confidence the analyst did not state and a confidence of zero are different
 * facts, and a dashboard that shows them identically is lying quietly.
 */

export function percent(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "n/a";
  return `${(value * 100).toFixed(digits)}%`;
}

export function decimal(value: number | null | undefined, digits = 3): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "n/a";
  return value.toFixed(digits);
}

export const LABEL_TEXT: Record<string, string> = {
  true_positive: "True positive",
  false_positive: "False positive",
  benign: "Benign",
  suspicious: "Suspicious",
  confirmed_malicious: "Confirmed malicious",
  uncertain: "Uncertain",
};

/** Labels that may become training examples. Mirrors the backend vocabulary. */
export const TRAINING_ELIGIBLE = new Set([
  "true_positive",
  "false_positive",
  "benign",
  "confirmed_malicious",
]);

export const DRIFT_STATUS_STYLE: Record<string, string> = {
  stable: "text-emerald-300 bg-emerald-500/10 border-emerald-500/30",
  moderate: "text-amber-300 bg-amber-500/10 border-amber-500/30",
  significant: "text-rose-300 bg-rose-500/10 border-rose-500/30",
};

export const PROPOSAL_STATUS_STYLE: Record<string, string> = {
  pending: "text-amber-300 bg-amber-500/10 border-amber-500/30",
  approved: "text-cyan-300 bg-cyan-500/10 border-cyan-500/30",
  deployed: "text-emerald-300 bg-emerald-500/10 border-emerald-500/30",
  rejected: "text-slate-300 bg-slate-500/10 border-slate-500/30",
  rolled_back: "text-rose-300 bg-rose-500/10 border-rose-500/30",
  superseded: "text-slate-300 bg-slate-500/10 border-slate-500/30",
};

export function statusText(status: string): string {
  return status.replace(/_/g, " ");
}
