/** Response action requests and their approvals (V9 Phase E). */

import { api } from "./client";

export type ResponseActionStatus =
  | "requested"
  | "approved"
  | "rejected"
  | "withdrawn";

/**
 * Containment actions AEGISX can be asked to perform.
 *
 * Names only. Nothing in the platform executes any of them - approving one
 * records a decision, and that is the whole of it in this version.
 */
export type ResponseActionType =
  | "isolate_endpoint"
  | "disable_account"
  | "block_indicator"
  | "revoke_session"
  | "quarantine_file";

export interface ApiResponseAction {
  requestRef: string;
  incidentRef: string;
  actionType: string;
  parameters: Record<string, unknown>;
  parametersDigest: string;
  justification: string;
  status: ResponseActionStatus;
  requestedBy: string;
  requestedByRole: string | null;
  requestedAt: string;
  decidedBy: string | null;
  decidedByRole: string | null;
  decidedAt: string | null;
  decisionReason: string | null;
  /** The evidence binding this approval was taken on. Null while pending. */
  decisionRef: string | null;
  executed: boolean;
  executionNote: string;
}

export interface ApiResponseActionList {
  incidentId: string;
  total: number;
  pending: number;
  items: ApiResponseAction[];
}

export async function fetchResponseActions(
  incidentId: string,
): Promise<ApiResponseActionList> {
  const { data } = await api.get<ApiResponseActionList>(
    `/incidents/${incidentId}/response-actions`,
  );
  return data;
}

export async function requestResponseAction(
  incidentId: string,
  input: {
    actionType: ResponseActionType;
    parameters: Record<string, unknown>;
    justification: string;
  },
): Promise<ApiResponseAction> {
  const { data } = await api.post<ApiResponseAction>(
    `/incidents/${incidentId}/response-actions`,
    input,
  );
  return data;
}

/**
 * Approve a request.
 *
 * `expectedEvidenceDigest` is required by the server, not optional as it is on
 * a lifecycle transition: an approval must state which evidence it was given,
 * and is refused with 409 if that evidence has moved since.
 */
export async function approveResponseAction(
  incidentId: string,
  requestRef: string,
  input: { expectedEvidenceDigest: string; reason?: string },
): Promise<ApiResponseAction> {
  const { data } = await api.post<ApiResponseAction>(
    `/incidents/${incidentId}/response-actions/${requestRef}/approve`,
    input,
  );
  return data;
}

export async function rejectResponseAction(
  incidentId: string,
  requestRef: string,
  input: { reason: string },
): Promise<ApiResponseAction> {
  const { data } = await api.post<ApiResponseAction>(
    `/incidents/${incidentId}/response-actions/${requestRef}/reject`,
    input,
  );
  return data;
}
