import type { LucideIcon } from "lucide-react";
import { Inbox } from "lucide-react";

import { cn } from "@/lib/utils";

interface EmptyStateProps {
  title: string;
  description?: string;
  icon?: LucideIcon;
  action?: React.ReactNode;
  className?: string;
}

/** Shown when a query succeeded but returned nothing. */
export default function EmptyState({
  title,
  description,
  icon: Icon = Inbox,
  action,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-800 bg-slate-900/50 px-6 py-12 text-center",
        className,
      )}
    >
      <Icon className="mb-4 text-slate-600" size={36} />

      <h3 className="text-base font-semibold text-slate-200">{title}</h3>

      {description && (
        <p className="mt-2 max-w-md text-sm text-slate-500">{description}</p>
      )}

      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}
