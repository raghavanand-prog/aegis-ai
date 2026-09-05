/** Evidence providers and their health (V9 Phase F). */

import { api } from "./client";
import type { ComponentStatus } from "./types";

export interface ApiProviderHealth {
  status: ComponentStatus;
  /** Always present when the status is not healthy - the backend refuses to
   *  construct an unexplained degradation. */
  reason: string | null;
}

export interface ApiProvider {
  name: string;
  /** The evidence kinds this provider can emit. */
  produces: string[];
  /** Whether it reaches outside the platform. All built-ins are projections. */
  isExternal: boolean;
  health: ApiProviderHealth;
}

export interface ApiProviderList {
  /** The worst of the individual statuses. */
  status: ComponentStatus;
  total: number;
  degraded: number;
  providers: ApiProvider[];
}

export async function fetchProviders(): Promise<ApiProviderList> {
  const { data } = await api.get<ApiProviderList>("/providers");
  return data;
}
