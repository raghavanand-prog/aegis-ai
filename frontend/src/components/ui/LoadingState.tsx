import { cn } from "@/lib/utils";

interface LoadingStateProps {
  label?: string;
  className?: string;
}

/** Inline loading indicator for panels and lists. */
export default function LoadingState({
  label = "Loading...",
  className,
}: LoadingStateProps) {
  return (
    <div
      className={cn(
        "flex items-center justify-center gap-3 rounded-xl border border-slate-800 bg-slate-900/50 px-6 py-12 text-slate-400",
        className,
      )}
    >
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-700 border-t-cyan-400" />
      <span className="text-sm">{label}</span>
    </div>
  );
}

/** Placeholder block used while a chart or card is loading. */
export function SkeletonBlock({ className }: { className?: string }) {
  return (
    <div
      className={cn("animate-pulse rounded-xl bg-slate-800/60", className)}
      aria-hidden="true"
    />
  );
}
