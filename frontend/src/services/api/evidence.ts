/** Investigation evidence and its provenance (V9). */

import { api } from "./client";

/** What kind of claim a piece of evidence is. */
export type EvidenceOrigin =
  | "observed"
  | "derived"
  | "reported"
  | "analytic"
  | "simulated";

/** What the backend can actually promise about the stored record. */
export type EvidenceIntegrity = "append_only" | "write_once" | "mutable";

export interface ApiProvenance {
  provider: string;
  /** Typed pointer back to the source row: `"<type>:<id>"`. */
  sourceRef: string;
  origin: EvidenceOrigin;
  integrity: EvidenceIntegrity;
  /**
   * False for a mutable source: the content behind this item can change after
   * a decision was taken on it, and only the digest would show that it had.
   */
  tamperEvidentAtRest: boolean;
  /** When the thing happened. Null when the source genuinely does not know. */
  observedAt: string | null;
  /** When AEGISX recorded it. Never inferred from `observedAt`. */
  collectedAt: string;
  confidence: number | null;
  /** What the confidence measures. Always present when there is one. */
  confidenceBasis: string | null;
  incidentRef: string | null;
  eventRef: string | null;
  isSynthetic: boolean;
  extra: Record<string, unknown>;
}

export interface ApiEvidenceItem {
  evidenceId: string;
  kind: string;
  title: string;
  content: Record<string, unknown>;
  contentDigest: string;
  /** The text looks like an attempt to steer a language model. */
  containsInjectionAttempt: boolean;
  provenance: ApiProvenance;
}

export interface ApiDegradedProvider {
  provider: string;
  status: string;
  reason: string | null;
}

export interface ApiEvidenceSet {
  incidentId: string;
  manifestDigest: string;
  total: number;
  countsByKind: Record<string, number>;
  countsByOrigin: Record<string, number>;
  injectionFlagged: string[];
  /**
   * Providers that could not answer. Rendered separately from an empty item
   * list on purpose: "no evidence" and "we could not ask" are different facts.
   */
  degradedProviders: ApiDegradedProvider[];
  filters: Record<string, unknown>;
  items: ApiEvidenceItem[];
}

export async function fetchIncidentEvidence(
  incidentId: string,
  params?: { kind?: string; provider?: string },
): Promise<ApiEvidenceSet> {
  const { data } = await api.get<ApiEvidenceSet>(
    `/incidents/${incidentId}/evidence`,
    { params },
  );
  return data;
}

export async function fetchEvidenceItem(
  incidentId: string,
  evidenceId: string,
): Promise<ApiEvidenceItem> {
  const { data } = await api.get<ApiEvidenceItem>(
    `/incidents/${incidentId}/evidence/${evidenceId}`,
  );
  return data;
}
