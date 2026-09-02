import { ReactNode } from "react";
import clsx from "clsx";

type BadgeVariant =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "active"
  | "investigating"
  | "blocked"
  | "contained"
  | "resolved";

type BadgeProps = {
  children: ReactNode;
  variant: BadgeVariant;
};

const variantClasses: Record<BadgeVariant, string> = {
  critical:
    "bg-red-500/15 text-red-400 border border-red-500/30",

  high:
    "bg-orange-500/15 text-orange-400 border border-orange-500/30",

  medium:
    "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30",

  low:
    "bg-blue-500/15 text-blue-400 border border-blue-500/30",

  active:
    "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30",

  investigating:
    "bg-violet-500/15 text-violet-400 border border-violet-500/30",

  blocked:
    "bg-red-600/15 text-red-300 border border-red-600/30",

  contained:
    "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30",

  resolved:
    "bg-slate-500/15 text-slate-300 border border-slate-500/30",
};

export default function Badge({
  children,
  variant,
}: BadgeProps) {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wide",
        variantClasses[variant]
      )}
    >
      {children}
    </span>
  );
}