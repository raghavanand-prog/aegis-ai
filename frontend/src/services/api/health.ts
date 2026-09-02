/** System health endpoints. */

import { api } from "./client";
import type { ApiSystemHealth } from "./types";

export async function fetchSystemHealth(): Promise<ApiSystemHealth> {
  const { data } = await api.get<ApiSystemHealth>("/health/system");
  return data;
}
