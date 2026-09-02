import { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface CardProps {
  children: ReactNode;
  className?: string;
}

export default function Card({
  children,
  className,
}: CardProps) {
  return (
    <div
      className={cn(
        `
        rounded-2xl
        border
        border-border/70
        bg-gradient-to-br
        from-slate-950
        via-slate-900
        to-blue-950

        shadow-lg
        transition-all
        duration-300

        hover:border-blue-500/40
        hover:shadow-2xl
        hover:-translate-y-1

        backdrop-blur-xl
        overflow-hidden
        `,
        className
      )}
    >
      {children}
    </div>
  );
}