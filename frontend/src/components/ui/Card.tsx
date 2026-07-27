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
        border-border
        bg-gradient-to-br
        from-slate-950
        via-slate-900
        to-blue-950
        shadow-xl
        p-8
        `,
        className
      )}
    >
      {children}
    </div>
  );
}