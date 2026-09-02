import type { ReactElement, ReactNode } from "react";
import { render, type RenderOptions } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import { AuthContext, type AuthContextType } from "@/features/auth/context/authContextValue";
import type { ApiUser } from "@/services/api/types";

export const ANALYST: ApiUser = {
  id: 1,
  email: "analyst@aegisx.dev",
  fullName: "Test Analyst",
  role: "analyst",
  isActive: true,
  lastLoginAt: null,
  createdAt: new Date().toISOString(),
  permissions: [
    "events:read",
    "events:promote",
    "incidents:read",
    "incidents:create",
    "incidents:update",
    "analytics:read",
    "detection:read",
    "notifications:read",
  ],
};

export const VIEWER: ApiUser = {
  ...ANALYST,
  id: 2,
  email: "viewer@aegisx.dev",
  role: "viewer",
  permissions: ["events:read", "incidents:read", "analytics:read", "detection:read"],
};

function authValue(user: ApiUser | null): AuthContextType {
  return {
    isAuthenticated: user !== null,
    user,
    isRestoring: false,
    isLoggingIn: false,
    error: null,
    login: async () => {},
    logout: async () => {},
    clearError: () => {},
  };
}

interface Options extends Omit<RenderOptions, "wrapper"> {
  user?: ApiUser | null;
  route?: string;
}

/** Render a component with the providers the app supplies in production. */
export function renderWithProviders(ui: ReactElement, options: Options = {}) {
  const { user = ANALYST, route = "/", ...rest } = options;

  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
      mutations: { retry: false },
    },
  });

  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={[route]}>
          <AuthContext.Provider value={authValue(user)}>{children}</AuthContext.Provider>
        </MemoryRouter>
      </QueryClientProvider>
    );
  }

  return { queryClient, ...render(ui, { wrapper: Wrapper, ...rest }) };
}
