/**
 * Formatting rules for research numbers.
 *
 * The whole point of this section is that a reader can tell what a number
 * means, so formatting is not cosmetic here:
 *
 * - `null` renders as "n/a", never as "0%". Precision with no predictions is
 *   undefined, and drawing a zero bar for it would invent a measurement.
 * - Every rate is rendered with its unit. A bare "0.65" could be a threshold,
 *   a probability or an anomaly ranking, and those are different things.
 * - Score kinds are shown next to the number they describe, with the
 *   probability/ranking distinction preserved verbatim from the backend.
 */

export const NOT_AVAILABLE = "n/a";

/** A rate in [0,1] as a percentage. `null` stays `null`-shaped, not zero. */
export function percent(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined) return NOT_AVAILABLE;
  return `${(value * 100).toFixed(digits)}%`;
}

/** A raw number (MCC, AUC) that is not a percentage. */
export function decimal(value: number | null | undefined, digits = 3): string {
  if (value === null || value === undefined) return NOT_AVAILABLE;
  return value.toFixed(digits);
}

export function count(value: number | null | undefined): string {
  if (value === null || value === undefined) return NOT_AVAILABLE;
  return value.toLocaleString();
}

export function milliseconds(value: number | null | undefined): string {
  if (value === null || value === undefined) return NOT_AVAILABLE;
  if (value < 1) return `${(value * 1000).toFixed(0)} µs`;
  return `${value.toFixed(2)} ms`;
}

/**
 * True when a detector's number can be ordered, and therefore when a threshold
 * curve or an AUC means anything at all.
 */
export function isOrderedScore(scoreKind: string): boolean {
  return !scoreKind.startsWith("rule_hit");
}

/** Short label for a score kind, for use in a table cell. */
export function scoreKindLabel(scoreKind: string): string {
  if (scoreKind.startsWith("anomaly_score")) return "anomaly ranking";
  if (scoreKind.startsWith("probability")) return "probability";
  if (scoreKind.startsWith("risk_score")) return "risk score 0-100";
  if (scoreKind.startsWith("rule_hit")) return "binary rule hit";
  return scoreKind;
}

/**
 * The one-line caution that belongs beside a score of this kind. Returning
 * `null` means the number needs no caveat.
 */
export function scoreKindCaution(scoreKind: string): string | null {
  if (scoreKind.startsWith("anomaly_score")) {
    return "A ranking, not a probability. 0.70 does not mean 70% likely malicious.";
  }
  if (scoreKind.startsWith("rule_hit")) {
    return "A binary indicator with no ordering, so ROC-AUC and PR-AUC are undefined.";
  }
  if (scoreKind.startsWith("risk_score")) {
    return "AEGISX's weighted policy output, built from several signals. Not a model output.";
  }
  return null;
}

const DETECTOR_LABELS: Record<string, string> = {
  rules: "Rules only",
  isolation_forest: "Isolation Forest (fitted here)",
  isolation_forest_registered: "Isolation Forest (deployed artifact)",
  supervised_hgb: "Supervised (gradient boosting)",
  hybrid: "Hybrid (rules OR ML)",
  hybrid_risk: "Hybrid (production risk scoring)",
  ablation_ml_only: "ML only",
  ablation_rules_plus_ml: "Rules + ML",
  ablation_rules_plus_ml_risk: "Rules + ML (risk scoring)",
};

export function detectorLabel(name: string): string {
  return DETECTOR_LABELS[name] ?? name;
}

export const SPLIT_LABELS: Record<string, string> = {
  stratified_group: "Random (stratified, group-aware)",
  temporal: "Temporal (past → future)",
};

export function splitLabel(strategy: string): string {
  return SPLIT_LABELS[strategy] ?? strategy;
}
