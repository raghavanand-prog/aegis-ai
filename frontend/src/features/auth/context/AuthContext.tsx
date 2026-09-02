/**
 * Authentication state.
 *
 * Backed by the AEGISX API: credentials are verified server-side and the
 * returned JWT is what authorises every subsequent request and the WebSocket
 * stream. The UI keeps no notion of "logged in" that the backend has not
 * confirmed - on reload the stored token is validated against `/auth/me`
 * before the app treats the analyst as authenticated.
 */

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { ApiError, UNAUTHORIZED_EVENT } from "@/services/api/client";
import * as authApi from "@/services/api/auth";
import { clearToken, getToken } from "@/services/api/tokenStore";
import type { ApiUser } from "@/services/api/types";
import { realtime } from "@/services/realtime/socket";

import { AuthContext, type AuthContextType } from "./authContextValue";

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [user, setUser] = useState<ApiUser | null>(null);
  const [isRestoring, setIsRestoring] = useState(true);
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Restore a previous session: a token on its own proves nothing, so it is
  // exchanged for the current user before the app trusts it.
  useEffect(() => {
    let cancelled = false;

    async function restore() {
      if (!getToken()) {
        setIsRestoring(false);
        return;
      }
      try {
        const currentUser = await authApi.fetchCurrentUser();
        if (!cancelled) {
          setUser(currentUser);
          realtime.start();
        }
      } catch (err) {
        // An expired or revoked token is dropped; a backend outage leaves the
        // analyst signed out rather than pretending they are signed in.
        clearToken();
        if (!cancelled && err instanceof ApiError && err.isNetworkError) {
          setError(err.message);
        }
      } finally {
        if (!cancelled) setIsRestoring(false);
      }
    }

    void restore();
    return () => {
      cancelled = true;
    };
  }, []);

  // The API client raises this when the backend rejects our token mid-session.
  useEffect(() => {
    const handleUnauthorized = () => {
      setUser(null);
      realtime.stop();
      queryClient.clear();
    };
    window.addEventListener(UNAUTHORIZED_EVENT, handleUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, handleUnauthorized);
  }, [queryClient]);

  const login = useCallback(async (email: string, password: string) => {
    setIsLoggingIn(true);
    setError(null);
    try {
      const authenticated = await authApi.login(email, password);
      // Drop anything cached before this session (including failures from the
      // unauthenticated state) so every query refetches with the new token.
      queryClient.clear();
      setUser(authenticated);
      realtime.start();
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : "Sign-in failed. Please try again.";
      setError(message);
      throw err;
    } finally {
      setIsLoggingIn(false);
    }
  }, [queryClient]);

  const logout = useCallback(async () => {
    realtime.stop();
    setUser(null);
    setError(null);
    queryClient.clear();
    await authApi.logout();
  }, [queryClient]);

  const value = useMemo<AuthContextType>(
    () => ({
      isAuthenticated: user !== null,
      user,
      isRestoring,
      isLoggingIn,
      error,
      login,
      logout,
      clearError: () => setError(null),
    }),
    [user, isRestoring, isLoggingIn, error, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
