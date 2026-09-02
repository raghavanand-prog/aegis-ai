/**
 * Axios instance used by every API module.
 *
 * Components never call axios directly - they go through the typed functions
 * in this folder, which keeps request shapes, error handling and auth in one
 * place.
 */

import axios, { AxiosError } from "axios";

import { clearToken, getToken } from "./tokenStore";

export const API_BASE_URL: string =
  import.meta.env.VITE_API_URL ?? "http://localhost:8000/api/v1";

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
  headers: { "Content-Type": "application/json" },
});

/** Normalized error every caller can rely on. */
export class ApiError extends Error {
  readonly status: number | null;
  readonly isNetworkError: boolean;
  readonly isAuthError: boolean;

  constructor(message: string, status: number | null, isNetworkError = false) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.isNetworkError = isNetworkError;
    this.isAuthError = status === 401;
  }
}

/** Fired when the backend rejects our token, so the app can log out cleanly. */
export const UNAUTHORIZED_EVENT = "aegisx:unauthorized";

function extractDetail(error: AxiosError): string {
  const data = error.response?.data as
    | { detail?: unknown; message?: string }
    | undefined;

  if (typeof data?.detail === "string") return data.detail;

  // FastAPI validation errors arrive as a list of {loc, msg, type}.
  if (Array.isArray(data?.detail)) {
    const first = data.detail[0] as { msg?: string } | undefined;
    if (first?.msg) return first.msg;
  }

  if (typeof data?.message === "string") return data.message;
  return error.message || "Unexpected error";
}

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    // No response at all: backend down, DNS failure, CORS, or timeout.
    if (!error.response) {
      return Promise.reject(
        new ApiError(
          "Cannot reach the AEGISX backend. Check that the API is running.",
          null,
          true,
        ),
      );
    }

    const status = error.response.status;

    if (status === 401) {
      clearToken();
      window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
    }

    return Promise.reject(new ApiError(extractDetail(error), status));
  },
);

/** Unauthenticated liveness probe, used to distinguish "down" from "logged out". */
export async function checkBackendHealth(): Promise<boolean> {
  try {
    const response = await axios.get(`${API_BASE_URL}/health`, { timeout: 5000 });
    // V2 reports healthy/degraded/unavailable; "ok" was the V1 wording.
    return ["healthy", "degraded", "ok"].includes(response.data?.status);
  } catch {
    return false;
  }
}
