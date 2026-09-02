/** Authentication endpoints. */

import { api } from "./client";
import { clearToken, setToken } from "./tokenStore";
import type { ApiToken, ApiUser } from "./types";

export async function login(email: string, password: string): Promise<ApiUser> {
  const { data } = await api.post<ApiToken>("/auth/login", { email, password });
  setToken(data.accessToken);
  // Permissions arrive alongside the user; the UI uses them to hide controls,
  // while the backend enforces the same matrix on every request.
  return { ...data.user, permissions: data.permissions };
}

export async function fetchCurrentUser(): Promise<ApiUser> {
  const { data } = await api.get<ApiUser>("/auth/me");
  return data;
}

/** Records the logout server-side, then drops the local token regardless. */
export async function logout(): Promise<void> {
  try {
    await api.post("/auth/logout");
  } catch {
    // A failed audit write must never trap the analyst in a session.
  } finally {
    clearToken();
  }
}
