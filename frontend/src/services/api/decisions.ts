/** Decision-bound evidence integrity (V9). */

import { api } from "./client";

/** How the evidence behind a decision has moved since it was taken. */
export type DriftVerdict = "unchanged" | "extended" | "refreshed" | "tampered";

export interface ApiChangedEvidence {
  evidenceId: string;
  integrity: string;
  kind: string;
  provider: string;
  digestAtDecision: string;
  digestNow: string;
}

export interface ApiDriftReport {
  verdict: DriftVerdict;
  severity: number;
  /**
   * True when what the decision *rested on* has moved. `extended` is false —
   * new evidence does not change the basis of the earlier decision — while
   * `refreshed` is true, because a routine cause does not make a changed
   * verdict a routine consequence.
   */
  underminesDecision: boolean;
  manifestMatches: boolean;
  manifestAtDecision: string;
  manifestNow: string;
  added: string[];
  removed: string[];
  changed: ApiChangedEvidence[];
  /** False when the decision-time snapshot was truncated, so which item moved
   *  may be unanswerable. Detection is unaffected. */
  attributionComplete: boolean;
  /** Providers unreachable when the decision was taken: it was made on
   *  partial evidence. */
  degradedAtDecision: Array<Record<string, unknown>>;
}

export interface ApiDecisionBinding {
  decisionRef: string;
  decisionType: string;
  incidentRef: string;
  fromState: string | null;
  toState: string;
  reason: string | null;
  decidedBy: string;
  decidedByRole: string | null;
  decidedAt: string;
  manifestDigest: string;
  evidenceCount: number;
  drift: ApiDriftReport;
}

export interface ApiDecisionList {
  incidentId: string;
  total: number;
  /** Worst verdict across every decision, so an incident can be badged
   *  without walking the list. */
  worstVerdict: DriftVerdict;
  items: ApiDecisionBinding[];
}

export async function fetchIncidentDecisions(
  incidentId: string,
): Promise<ApiDecisionList> {
  const { data } = await api.get<ApiDecisionList>(
    `/incidents/${incidentId}/decisions`,
  );
  return data;
}
