import { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface CardHeaderProps {
  title: string;
  subtitle?: string;
  action?: ReactNode;
  className?: string;
}

export default function CardHeader({
  title,
  subtitle,
  action,
  className,
}: CardHeaderProps) {
  return (
    <div
      className={cn(
        "flex items-start justify-between border-b border-border/60 p-6",
        className
      )}
    >
      <div>
        <h2 className="text-lg font-semibold tracking-tight text-white">
          {title}
        </h2>

        {subtitle && (
          <p className="mt-1 text-sm text-slate-400">
            {subtitle}
          </p>
        )}
      </div>

      {action}
    </div>
  );
}