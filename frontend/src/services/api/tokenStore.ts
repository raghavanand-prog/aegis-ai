/**
 * Access token storage.
 *
 * Kept in its own module so the axios client and the auth context can both
 * reach it without importing each other.
 *
 * Security note: the token lives in localStorage, which is readable by any
 * script running on this origin. That is an accepted V1 trade-off for a
 * single-page app with no server-rendered session; moving to an httpOnly
 * refresh cookie plus a short-lived in-memory access token is a V2 task.
 */

const TOKEN_KEY = "aegisx.accessToken";

let cachedToken: string | null = null;

export function getToken(): string | null {
  if (cachedToken !== null) return cachedToken;
  try {
    cachedToken = window.localStorage.getItem(TOKEN_KEY);
  } catch {
    cachedToken = null;
  }
  return cachedToken;
}

export function setToken(token: string): void {
  cachedToken = token;
  try {
    window.localStorage.setItem(TOKEN_KEY, token);
  } catch {
    // Private browsing / storage disabled: the token stays in memory only.
  }
}

export function clearToken(): void {
  cachedToken = null;
  try {
    window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    // ignore
  }
}
