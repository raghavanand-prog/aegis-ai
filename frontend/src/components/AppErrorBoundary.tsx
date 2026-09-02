import { AlertOctagon } from "lucide-react";
import type { ReactNode } from "react";

import ErrorBoundary from "./ErrorBoundary";

/**
 * Root boundary: the last line of defence.
 *
 * A crash here means the shell itself failed, so the fallback deliberately
 * avoids the app's own components (they may be what broke) and offers a
 * reload.
 */
export default function AppErrorBoundary({ children }: { children: ReactNode }) {
  return (
    <ErrorBoundary
      label="AEGISX console"
      fallback={(error) => (
        <div className="flex min-h-screen flex-col items-center justify-center bg-slate-950 px-6 text-center">
          <AlertOctagon className="mb-4 text-red-400" size={40} />

          <h1 className="text-2xl font-bold text-white">The console hit an unexpected error</h1>

          <p className="mt-3 max-w-lg text-sm text-slate-400">
            Your session and data are unaffected - this is a rendering failure in the
            interface. Reloading usually clears it.
          </p>

          <p className="mt-3 max-w-lg truncate text-xs text-slate-600">{error.message}</p>

          <button
            onClick={() => window.location.reload()}
            className="mt-6 rounded-xl bg-blue-600 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-blue-500"
          >
            Reload AEGISX
          </button>
        </div>
      )}
    >
      {children}
    </ErrorBoundary>
  );
}
