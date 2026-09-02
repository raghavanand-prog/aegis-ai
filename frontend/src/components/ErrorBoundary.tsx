import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertOctagon, RefreshCw } from "lucide-react";

interface Props {
  children: ReactNode;
  /** Shown instead of the default panel. */
  fallback?: (error: Error, reset: () => void) => ReactNode;
  /** Name used in the message and the console log, e.g. "Threat feed". */
  label?: string;
  /** Changing any of these values clears the error (e.g. on route change). */
  resetKeys?: unknown[];
}

interface State {
  error: Error | null;
}

/**
 * Stops one broken component from taking down the console.
 *
 * React unmounts the whole tree when a render throws, so without a boundary a
 * single bad value in one panel blanks the entire SOC view - exactly when an
 * analyst needs the rest of the screen. Boundaries are placed per panel as
 * well as at the app root, so a failure stays inside the card it came from.
 */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidUpdate(previous: Props): void {
    const { resetKeys } = this.props;
    if (!this.state.error || !resetKeys) return;

    const previousKeys = previous.resetKeys ?? [];
    const changed =
      resetKeys.length !== previousKeys.length ||
      resetKeys.some((key, index) => key !== previousKeys[index]);

    if (changed) this.setState({ error: null });
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Kept to the console on purpose: shipping UI errors to the backend would
    // need a consent and PII story that V2 does not have.
    console.error(`[AEGISX] ${this.props.label ?? "Component"} crashed`, error, info);
  }

  reset = (): void => this.setState({ error: null });

  render(): ReactNode {
    const { error } = this.state;
    const { children, fallback, label } = this.props;

    if (!error) return children;
    if (fallback) return fallback(error, this.reset);

    return (
      <div
        role="alert"
        className="flex flex-col items-center justify-center rounded-xl border border-amber-500/30 bg-amber-500/5 px-6 py-10 text-center"
      >
        <AlertOctagon className="mb-3 text-amber-400" size={28} />

        <h3 className="text-base font-semibold text-amber-100">
          {label ? `${label} failed to render` : "This section failed to render"}
        </h3>

        <p className="mt-2 max-w-md text-sm text-slate-400">
          The rest of the console is still working. If this keeps happening, the
          details are in the browser console.
        </p>

        <p className="mt-2 max-w-md truncate text-xs text-slate-600">{error.message}</p>

        <button
          onClick={this.reset}
          className="mt-5 inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-slate-200 transition hover:border-slate-600 hover:bg-slate-800"
        >
          <RefreshCw size={15} />
          Try again
        </button>
      </div>
    );
  }
}
