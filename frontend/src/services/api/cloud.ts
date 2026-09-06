/** Cloud security posture (V9 Phase G). */

import { api } from "./client";

export type CloudFindingSeverity = "Critical" | "High" | "Medium" | "Low";

export interface ApiCloudResource {
  provider: string;
  account: string;
  region: string | null;
  service: string;
  resourceType: string;
  resourceId: string;
}

export interface ApiCloudFinding {
  findingId: string;
  checkId: string;
  title: string;
  description: string;
  severity: CloudFindingSeverity;
  /** The hardening theme in words. Never a benchmark identifier. */
  control: string | null;
  resource: ApiCloudResource;
  detail: Record<string, unknown>;
  sourceFile: string | null;
  /** Always true in this version. */
  isSimulated: boolean;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface ApiCloudFindingPage {
  total: number;
  limit: number;
  offset: number;
  items: ApiCloudFinding[];
  /** The backend's own statement that none of this is a real cloud scan. */
  note: string;
}

export async function fetchCloudFindings(
  params: { account?: string; severity?: CloudFindingSeverity; limit?: number } = {},
): Promise<ApiCloudFindingPage> {
  const { data } = await api.get<ApiCloudFindingPage>("/cloud/findings", { params });
  return data;
}
