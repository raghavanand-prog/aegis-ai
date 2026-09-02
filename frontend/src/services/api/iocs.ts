/** Indicator of compromise endpoints. */

import { api } from "./client";
import type { ApiIOC, Page } from "./types";

export interface IOCQuery {
  type?: string;
  search?: string;
  limit?: number;
}

export async function fetchIOCs(query: IOCQuery = {}): Promise<ApiIOC[]> {
  const { data } = await api.get<Page<ApiIOC>>("/iocs", {
    params: {
      limit: query.limit ?? 100,
      ...(query.type ? { type: query.type } : {}),
      ...(query.search ? { search: query.search } : {}),
    },
  });
  return data.items;
}
