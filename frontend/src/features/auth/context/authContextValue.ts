/**
 * Auth context object and its type.
 *
 * Kept apart from the provider component so the provider file only exports
 * components (React Fast Refresh requirement).
 */

import { createContext } from "react";

import type { ApiUser } from "@/services/api/types";

export interface AuthContextType {
  isAuthenticated: boolean;
  user: ApiUser | null;
  /** True while a stored session is being validated on first load. */
  isRestoring: boolean;
  isLoggingIn: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  clearError: () => void;
}

export const AuthContext = createContext<AuthContextType>({
  isAuthenticated: false,
  user: null,
  isRestoring: true,
  isLoggingIn: false,
  error: null,
  login: async () => {},
  logout: async () => {},
  clearError: () => {},
});
