import { AlertTriangle, RefreshCw, WifiOff } from "lucide-react";

import { ApiError } from "@/services/api/client";
import { cn } from "@/lib/utils";

interface ErrorStateProps {
  error: unknown;
  onRetry?: () => void;
  title?: string;
  className?: string;
}

function describe(error: unknown): { title: string; detail: string; offline: boolean } {
  if (error instanceof ApiError) {
    if (error.isNetworkError) {
      return {
        title: "Backend unreachable",
        detail:
          "AEGISX cannot reach the API. Check that the backend is running and that VITE_API_URL points at it.",
        offline: true,
      };
    }
    if (error.isAuthError) {
      return {
        title: "Session expired",
        detail: "Your session is no longer valid. Sign in again to continue.",
        offline: false,
      };
    }
    return { title: "Request failed", detail: error.message, offline: false };
  }

  return {
    title: "Something went wrong",
    detail: error instanceof Error ? error.message : "Unexpected error.",
    offline: false,
  };
}

/** Uniform error panel: says what broke and offers a way forward. */
export default function ErrorState({
  error,
  onRetry,
  title,
  className,
}: ErrorStateProps) {
  const described = describe(error);
  const Icon = described.offline ? WifiOff : AlertTriangle;

  return (
    <div
      role="alert"
      className={cn(
        "flex flex-col items-center justify-center rounded-xl border border-red-500/25 bg-red-500/5 px-6 py-10 text-center",
        className,
      )}
    >
      <Icon className="mb-4 text-red-400" size={32} />

      <h3 className="text-base font-semibold text-red-200">
        {title ?? described.title}
      </h3>

      <p className="mt-2 max-w-md text-sm text-slate-400">{described.detail}</p>

      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-5 inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-slate-200 transition hover:border-slate-600 hover:bg-slate-800"
        >
          <RefreshCw size={15} />
          Try again
        </button>
      )}
    </div>
  );
}
